import 'dotenv/config'
import crypto from 'node:crypto'
import express from 'express'
import { initStore, listMessages, getMessage, markRead, mailboxStats, saveMessage } from './store.mjs'
import { mailConfig, sendMail, startMailServers } from './mail.mjs'

const app = express()
const port = Number(process.env.WEB_PORT || 8787)
const sessions = new Map()
const account = (process.env.MAIL_USER || `admin@${mailConfig.domain}`).toLowerCase()
const password = process.env.MAIL_PASSWORD

if (!password) {
  throw new Error('MAIL_PASSWORD is required. Copy server/.env.example to server/.env and set it before starting.')
}

app.use(express.json({ limit: '2mb' }))
app.use((req, res, next) => {
  const allowedOrigin = process.env.CLIENT_ORIGIN || '*'
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin)
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS')
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})

function auth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '')
  if (!token || !sessions.has(token)) return res.status(401).json({ error: '登录已失效' })
  req.user = sessions.get(token)
  next()
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'wpyw.mail', hostname: mailConfig.hostname, domain: mailConfig.domain })
})

app.get('/api/config', auth, (_req, res) => {
  res.json({
    domain: mailConfig.domain,
    hostname: mailConfig.hostname,
    account,
    protocols: {
      smtp: Number(process.env.SMTP_PORT || 25),
      submission: Number(process.env.SUBMISSION_PORT || 587),
      api: port,
    },
  })
})

app.post('/api/login', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim()
  const pass = String(req.body?.password || '')
  if (email !== account || pass !== password) return res.status(401).json({ error: '邮箱或密码不正确' })
  const token = crypto.randomBytes(32).toString('hex')
  sessions.set(token, { email: account, createdAt: Date.now() })
  res.json({ token, user: { email: account, domain: mailConfig.domain } })
})

app.post('/api/logout', auth, (req, res) => {
  const token = req.headers.authorization.replace(/^Bearer\s+/i, '')
  sessions.delete(token)
  res.json({ ok: true })
})

app.get('/api/me', auth, async (req, res) => {
  res.json({ user: req.user, stats: await mailboxStats() })
})

app.get('/api/messages', auth, async (req, res) => {
  const folder = ['inbox', 'sent', 'drafts', 'archive'].includes(req.query.folder) ? req.query.folder : 'inbox'
  res.json({ messages: await listMessages(folder, String(req.query.q || '')) })
})

app.get('/api/messages/:id', auth, async (req, res) => {
  const message = await getMessage(req.params.id)
  if (!message) return res.status(404).json({ error: '邮件不存在' })
  await markRead(req.params.id)
  res.json({ message: { ...message, unread: false } })
})

app.post('/api/send', auth, async (req, res) => {
  const { to, subject, text, html } = req.body || {}
  if (!to || !subject || !text) return res.status(400).json({ error: '收件人、主题和正文不能为空' })
  try {
    const result = await sendMail({ to, subject, text, html })
    await saveMessage({ folder: 'sent', from: account, to, subject, text, html, unread: false })
    res.json({ ok: true, result })
  } catch (error) {
    console.error('[send]', error)
    res.status(502).json({ error: `发信失败：${error.message}` })
  }
})

app.use('/api', (_req, res) => res.status(404).json({ error: 'API endpoint not found' }))

await initStore()
app.listen(port, '0.0.0.0', () => console.log(`[web] wpyw.mail listening on ${port}`))
startMailServers()

process.on('SIGINT', () => process.exit(0))
process.on('SIGTERM', () => process.exit(0))
