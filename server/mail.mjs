import fs from 'node:fs'
import dns from 'node:dns/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { simpleParser } from 'mailparser'
import nodemailer from 'nodemailer'
import { SMTPServer } from 'smtp-server'
import { saveMessage } from './store.mjs'

const domain = (process.env.MAIL_DOMAIN || 'wpyw.site').toLowerCase()
const account = (process.env.MAIL_USER || `admin@${domain}`).toLowerCase()
const password = process.env.MAIL_PASSWORD
const hostname = process.env.MAIL_HOSTNAME || `mail.${domain}`
const serverDir = path.dirname(fileURLToPath(import.meta.url))
const dataDir = process.env.MAIL_DATA_DIR || path.join(serverDir, 'data')

if (!password) {
  throw new Error('MAIL_PASSWORD is required. Copy server/.env.example to server/.env and set it before starting.')
}

function addressOf(value) {
  if (!value) return ''
  if (typeof value === 'string') return value.toLowerCase()
  if (Array.isArray(value)) return addressOf(value[0])
  if (value.value?.[0]?.address) return value.value[0].address.toLowerCase()
  if (value.address) return value.address.toLowerCase()
  return ''
}

function addressList(value) {
  if (!value) return []
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap(addressList)
  if (value.value) return value.value.map((item) => item.address || item.name).filter(Boolean)
  return value.address ? [value.address] : []
}

function isLocalAddress(address) {
  return address.toLowerCase().endsWith(`@${domain}`)
}

async function storeIncoming(parsed, envelopeRecipients = []) {
  const attachments = []
  for (const attachment of parsed.attachments || []) {
    const filename = `${Date.now()}-${attachment.filename || 'attachment.bin'}`.replace(/[^a-zA-Z0-9._-]/g, '_')
    const attachmentDir = path.join(dataDir, 'attachments')
    await fs.promises.mkdir(attachmentDir, { recursive: true })
    await fs.promises.writeFile(path.join(attachmentDir, filename), attachment.content)
    attachments.push({ filename: attachment.filename || filename, storedAs: filename, contentType: attachment.contentType })
  }

  const to = envelopeRecipients.length ? envelopeRecipients : addressList(parsed.to)
  await saveMessage({
    folder: 'inbox',
    from: parsed.from?.text || addressOf(parsed.from),
    to: to.join(', '),
    subject: parsed.subject || '(无主题)',
    text: parsed.text || '',
    html: typeof parsed.html === 'string' ? parsed.html : '',
    date: parsed.date?.toISOString() || new Date().toISOString(),
    unread: true,
    attachments,
    messageId: parsed.messageId || '',
  })
}

async function parseAndRoute(stream, session, submission) {
  const parsed = await simpleParser(stream)
  const envelopeRecipients = session.envelope.rcptTo.map((item) => item.address)

  if (!submission) {
    await storeIncoming(parsed, envelopeRecipients)
    return
  }

  const recipients = envelopeRecipients.length ? envelopeRecipients : addressList(parsed.to)
  if (!recipients.length) throw new Error('No recipients in submitted message')
  await sendMail({
    to: recipients,
    subject: parsed.subject || '(无主题)',
    text: parsed.text || '',
    html: typeof parsed.html === 'string' ? parsed.html : undefined,
  })
  await saveMessage({
    folder: 'sent',
    from: account,
    to: recipients.join(', '),
    subject: parsed.subject || '(无主题)',
    text: parsed.text || '',
    html: typeof parsed.html === 'string' ? parsed.html : '',
    date: parsed.date?.toISOString() || new Date().toISOString(),
    unread: false,
    messageId: parsed.messageId || '',
  })
}

function tlsOptions() {
  const keyPath = process.env.SMTP_TLS_KEY
  const certPath = process.env.SMTP_TLS_CERT
  if (!keyPath || !certPath || !fs.existsSync(keyPath) || !fs.existsSync(certPath)) return {}
  return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }
}

function makeSmtpServer({ submission = false } = {}) {
  const options = tlsOptions()
  return new SMTPServer({
    name: hostname,
    secure: false,
    ...options,
    authOptional: !submission,
    allowInsecureAuth: false,
    onAuth(auth, _session, callback) {
      if (auth.username?.toLowerCase() === account && auth.password === password) {
        return callback(null, { user: account })
      }
      const error = new Error('Invalid username or password')
      error.responseCode = 535
      return callback(error)
    },
    onMailFrom(address, _session, callback) {
      if (submission && address.address.toLowerCase() !== account) {
        const error = new Error('Sender address must match the authenticated mailbox')
        error.responseCode = 553
        return callback(error)
      }
      callback()
    },
    onRcptTo(address, _session, callback) {
      const recipient = address.address.toLowerCase()
      if (!submission && !isLocalAddress(recipient)) {
        const error = new Error('Relay denied')
        error.responseCode = 550
        return callback(error)
      }
      callback()
    },
    onData(stream, session, callback) {
      parseAndRoute(stream, session, submission)
        .then(() => callback())
        .catch((error) => callback(error))
    },
  })
}

export function startMailServers() {
  const smtpPort = Number(process.env.SMTP_PORT || 25)
  const submissionPort = Number(process.env.SUBMISSION_PORT || 587)
  const inbound = makeSmtpServer({ submission: false })
  const submission = makeSmtpServer({ submission: true })

  inbound.listen(smtpPort, '0.0.0.0', () => console.log(`[smtp] inbound listening on ${smtpPort}`))
  submission.listen(submissionPort, '0.0.0.0', () => console.log(`[smtp] submission listening on ${submissionPort}`))
  inbound.on('error', (error) => console.error('[smtp] inbound error', error.message))
  submission.on('error', (error) => console.error('[smtp] submission error', error.message))
  return { inbound, submission }
}

async function directTransport(recipient) {
  const recipientDomain = recipient.split('@').pop()
  const mxRecords = await dns.resolveMx(recipientDomain)
  if (!mxRecords.length) throw new Error(`No MX record found for ${recipientDomain}`)
  mxRecords.sort((a, b) => a.priority - b.priority)
  return nodemailer.createTransport({
    host: mxRecords[0].exchange,
    port: 25,
    secure: false,
    name: hostname,
    tls: {
      rejectUnauthorized: process.env.SMTP_DIRECT_TLS_REJECT_UNAUTHORIZED !== 'false',
    },
  })
}

function relayTransport() {
  const host = process.env.SMTP_RELAY_HOST
  if (!host) return null
  return nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_RELAY_PORT || 587),
    secure: process.env.SMTP_RELAY_SECURE === 'true',
    auth: process.env.SMTP_RELAY_USER
      ? { user: process.env.SMTP_RELAY_USER, pass: process.env.SMTP_RELAY_PASSWORD }
      : undefined,
  })
}

export async function sendMail({ to, subject, text, html }) {
  const sender = account
  const recipients = Array.isArray(to) ? to : String(to).split(',').map((item) => item.trim()).filter(Boolean)
  if (!recipients.length) throw new Error('Recipient is required')
  const transport = relayTransport() || await directTransport(recipients[0])
  const info = await transport.sendMail({ from: sender, to: recipients.join(', '), subject, text, html: html || undefined })
  transport.close?.()
  return { messageId: info.messageId, accepted: info.accepted }
}

export const mailConfig = { domain, account, hostname }
