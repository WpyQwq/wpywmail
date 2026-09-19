import fs from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const serverDir = path.dirname(fileURLToPath(import.meta.url))
const dataDir = process.env.MAIL_DATA_DIR || path.join(serverDir, 'data')
const messagesFile = path.join(dataDir, 'messages.json')

let writeQueue = Promise.resolve()

async function ensureStore() {
  await fs.mkdir(dataDir, { recursive: true })
  try {
    await fs.access(messagesFile)
  } catch {
    await fs.writeFile(messagesFile, '[]', 'utf8')
  }
}

async function readMessages() {
  await ensureStore()
  const raw = await fs.readFile(messagesFile, 'utf8')
  try {
    return JSON.parse(raw)
  } catch {
    return []
  }
}

function queueWrite(messages) {
  writeQueue = writeQueue.then(async () => {
    const tmp = `${messagesFile}.${process.pid}.tmp`
    await fs.writeFile(tmp, JSON.stringify(messages, null, 2), 'utf8')
    await fs.rename(tmp, messagesFile)
  })
  return writeQueue
}

export async function initStore() {
  await ensureStore()
  if (process.env.SEED_DEMO === 'true') {
    const messages = await readMessages()
    if (!messages.length) {
      const now = Date.now()
      await queueWrite([
        makeMessage({
          folder: 'inbox',
          from: 'Cloudflare <noreply@cloudflare.com>',
          to: process.env.MAIL_USER || 'admin@wpyw.site',
          subject: '你的 wpyw.site 邮件服务已准备就绪',
          text: '这是本地演示邮件。正式使用时，来自公网的 SMTP 邮件会自动进入这里。',
          date: new Date(now - 1000 * 60 * 12).toISOString(),
          unread: true,
        }),
        makeMessage({
          folder: 'inbox',
          from: '系统管理员 <admin@wpyw.site>',
          to: process.env.MAIL_USER || 'admin@wpyw.site',
          subject: '欢迎使用 wpyw.mail',
          text: '你可以从左侧开始管理收件箱，或点击右上角写信。',
          date: new Date(now - 1000 * 60 * 60 * 4).toISOString(),
          unread: false,
        }),
        makeMessage({
          folder: 'sent',
          from: process.env.MAIL_USER || 'admin@wpyw.site',
          to: 'hello@example.com',
          subject: '测试发信',
          text: 'SMTP 提交链路测试。',
          date: new Date(now - 1000 * 60 * 60 * 22).toISOString(),
          unread: false,
        }),
      ])
    }
  }
}

export function makeMessage(input) {
  const text = input.text || ''
  return {
    id: input.id || crypto.randomUUID(),
    folder: input.folder || 'inbox',
    from: input.from || '',
    to: input.to || '',
    subject: input.subject || '(无主题)',
    text,
    html: input.html || '',
    preview: input.preview || text.replace(/\s+/g, ' ').trim().slice(0, 140),
    date: input.date || new Date().toISOString(),
    unread: input.unread ?? true,
    attachments: input.attachments || [],
    messageId: input.messageId || '',
  }
}

export async function listMessages(folder = 'inbox', query = '') {
  const messages = await readMessages()
  const normalized = query.trim().toLowerCase()
  return messages
    .filter((message) => message.folder === folder)
    .filter((message) => {
      if (!normalized) return true
      return [message.from, message.to, message.subject, message.text]
        .join(' ')
        .toLowerCase()
        .includes(normalized)
    })
    .sort((a, b) => new Date(b.date) - new Date(a.date))
    .map(({ text, html, ...summary }) => summary)
}

export async function getMessage(id) {
  const messages = await readMessages()
  return messages.find((message) => message.id === id) || null
}

export async function saveMessage(input) {
  const messages = await readMessages()
  const message = makeMessage(input)
  messages.push(message)
  await queueWrite(messages)
  return message
}

export async function markRead(id) {
  const messages = await readMessages()
  const index = messages.findIndex((message) => message.id === id)
  if (index < 0) return null
  messages[index].unread = false
  await queueWrite(messages)
  return messages[index]
}

export async function mailboxStats() {
  const messages = await readMessages()
  return {
    inbox: messages.filter((message) => message.folder === 'inbox').length,
    unread: messages.filter((message) => message.folder === 'inbox' && message.unread).length,
    sent: messages.filter((message) => message.folder === 'sent').length,
    drafts: messages.filter((message) => message.folder === 'drafts').length,
  }
}
