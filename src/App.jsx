import { useEffect, useMemo, useState } from 'react'
import {
  Archive,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  CircleUserRound,
  Clock3,
  Inbox,
  LogOut,
  Mail,
  Menu,
  MoreHorizontal,
  Paperclip,
  PenLine,
  Plus,
  Search,
  Send,
  Settings,
  ShieldCheck,
  Star,
  Trash2,
  X,
} from 'lucide-react'

const API = '/api'

async function request(path, options = {}, token) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.error || '请求失败')
  return data
}

const folders = [
  { id: 'inbox', label: '收件箱', icon: Inbox },
  { id: 'sent', label: '已发送', icon: Send },
  { id: 'drafts', label: '草稿', icon: PenLine },
  { id: 'archive', label: '归档', icon: Archive },
]

function formatDate(value, detail = false) {
  const date = new Date(value)
  if (detail) return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(date)
  const now = new Date()
  if (date.toDateString() === now.toDateString()) return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit' }).format(date)
  return new Intl.DateTimeFormat('zh-CN', { month: 'short', day: 'numeric' }).format(date)
}

function senderName(value = '') {
  const match = value.match(/^(.+?)\s*<[^>]+>$/)
  if (match) return match[1].replace(/^"|"$/g, '')
  return value.split('@')[0] || value
}

function Login({ onLogin }) {
  const [email, setEmail] = useState('admin@wpyw.site')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(event) {
    event.preventDefault()
    setLoading(true)
    setError('')
    try {
      const data = await request('/login', { method: 'POST', body: JSON.stringify({ email, password }) })
      onLogin(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="login-shell">
      <section className="login-card">
        <div className="brand-lockup"><span className="brand-mark"><Mail size={18} /></span><span>wpyw.mail</span></div>
        <div className="login-copy">
          <p className="eyebrow">PRIVATE MAIL SERVER</p>
          <h1>你的邮件，留在自己的服务器上。</h1>
          <p>通过安全连接访问 wpyw.site 的收发件箱。</p>
        </div>
        <form onSubmit={submit} className="login-form">
          <label>邮箱地址<input value={email} onChange={(event) => setEmail(event.target.value)} type="email" autoComplete="username" /></label>
          <label>密码<input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" placeholder="输入服务器邮箱密码" /></label>
          {error && <div className="form-error">{error}</div>}
          <button className="primary-button" disabled={loading}>{loading ? '正在登录…' : '进入邮箱'}<ChevronRight size={17} /></button>
        </form>
        <div className="login-foot"><ShieldCheck size={15} /> 邮件服务运行在你的 Windows 服务器上</div>
      </section>
      <div className="login-orbit orbit-a" /><div className="login-orbit orbit-b" />
    </main>
  )
}

function Sidebar({ folder, setFolder, stats, onCompose, onLogout, mobileOpen, onClose }) {
  return (
    <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
      <div className="sidebar-top">
        <div className="brand-lockup"><span className="brand-mark"><Mail size={18} /></span><span>wpyw.mail</span></div>
        <button className="icon-button mobile-close" onClick={onClose}><X size={18} /></button>
      </div>
      <button className="compose-button" onClick={onCompose}><Plus size={17} />写信</button>
      <nav className="folder-nav">
        <p className="nav-caption">邮箱</p>
        {folders.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => { setFolder(id); onClose() }} className={`folder-item ${folder === id ? 'active' : ''}`}>
            <Icon size={17} /><span>{label}</span>{id === 'inbox' && stats.unread > 0 && <b>{stats.unread}</b>}
          </button>
        ))}
      </nav>
      <div className="sidebar-spacer" />
      <div className="server-status"><span className="status-dot" /><div><strong>服务器在线</strong><small>mail.wpyw.site</small></div></div>
      <div className="sidebar-bottom">
        <button className="folder-item"><Settings size={17} /><span>设置</span></button>
        <button className="folder-item" onClick={onLogout}><LogOut size={17} /><span>退出登录</span></button>
      </div>
    </aside>
  )
}

function MessageRow({ message, selected, onSelect }) {
  return (
    <button className={`message-row ${selected ? 'selected' : ''} ${message.unread ? 'unread' : ''}`} onClick={() => onSelect(message.id)}>
      <span className="sender-avatar">{senderName(message.from).slice(0, 1).toUpperCase()}</span>
      <span className="message-row-main"><strong>{senderName(message.from)}</strong><span>{message.subject}</span><small>{message.preview || '没有正文预览'}</small></span>
      <span className="message-row-meta"><time>{formatDate(message.date)}</time>{message.attachments?.length > 0 && <Paperclip size={14} />}</span>
    </button>
  )
}

function Reader({ message, onBack, onCompose }) {
  if (!message) return <section className="reader empty-reader"><div className="empty-icon"><Mail size={22} /></div><h2>选择一封邮件</h2><p>从左侧收件箱中选择邮件，在这里查看内容。</p></section>
  return (
    <section className="reader">
      <div className="reader-toolbar"><button className="icon-button mobile-back" onClick={onBack}><ArrowLeft size={18} /></button><div className="reader-actions"><button className="icon-button" title="归档"><Archive size={17} /></button><button className="icon-button" title="删除"><Trash2 size={17} /></button><button className="icon-button" title="更多"><MoreHorizontal size={18} /></button></div></div>
      <article className="message-detail">
        <div className="message-detail-head"><div className="sender-avatar large">{senderName(message.from).slice(0, 1).toUpperCase()}</div><div><h1>{message.subject}</h1><div className="sender-line"><strong>{senderName(message.from)}</strong><span>&lt;{message.from.match(/<([^>]+)>/)?.[1] || message.from}&gt;</span></div><div className="recipient-line">发送给 {message.to || '我'} · {formatDate(message.date, true)}</div></div><button className="icon-button"><Star size={18} /></button></div>
        <div className="message-body">{message.html ? <div dangerouslySetInnerHTML={{ __html: message.html }} /> : (message.text || '').split('\n').map((line, index) => <p key={index}>{line || '\u00a0'}</p>)}</div>
        {message.attachments?.length > 0 && <div className="attachments"><p>附件</p>{message.attachments.map((item) => <div className="attachment" key={item.storedAs}><Paperclip size={15} />{item.filename}</div>)}</div>}
        <div className="reply-row"><button className="secondary-button" onClick={() => onCompose({ to: message.from.match(/<([^>]+)>/)?.[1] || message.from, subject: `Re: ${message.subject}` })}><ArrowLeft size={16} />回复</button><button className="secondary-button" onClick={() => onCompose({ to: message.from.match(/<([^>]+)>/)?.[1] || message.from, subject: `Fwd: ${message.subject}` })}>转发</button></div>
      </article>
    </section>
  )
}

function Compose({ initial = {}, onClose, onSent, token }) {
  const [to, setTo] = useState(initial.to || '')
  const [subject, setSubject] = useState(initial.subject || '')
  const [text, setText] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')

  async function send(event) {
    event.preventDefault()
    setSending(true)
    setError('')
    try {
      await request('/send', { method: 'POST', body: JSON.stringify({ to, subject, text }) }, token)
      onSent()
    } catch (err) {
      setError(err.message)
    } finally {
      setSending(false)
    }
  }

  return <div className="compose-overlay"><form className="compose-panel" onSubmit={send}><header><div><span className="compose-title">新邮件</span><small>从 admin@wpyw.site 发送</small></div><button type="button" className="icon-button" onClick={onClose}><X size={18} /></button></header><label>收件人<input autoFocus value={to} onChange={(event) => setTo(event.target.value)} placeholder="name@example.com" /></label><label>主题<input value={subject} onChange={(event) => setSubject(event.target.value)} placeholder="输入主题" /></label><textarea value={text} onChange={(event) => setText(event.target.value)} placeholder="写下你的内容…" required /><footer>{error && <span className="form-error">{error}</span>}<button type="button" className="secondary-button" onClick={onClose}>取消</button><button className="primary-button small" disabled={sending}><Send size={15} />{sending ? '发送中…' : '发送'}</button></footer></form></div>
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('wpyw-token'))
  const [user, setUser] = useState(null)
  const [folder, setFolder] = useState('inbox')
  const [messages, setMessages] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [selected, setSelected] = useState(null)
  const [stats, setStats] = useState({ inbox: 0, unread: 0, sent: 0, drafts: 0 })
  const [query, setQuery] = useState('')
  const [compose, setCompose] = useState(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const selectedSummary = useMemo(() => messages.find((item) => item.id === selectedId), [messages, selectedId])

  async function refresh(nextFolder = folder, nextQuery = query) {
    if (!token) return
    const [list, me] = await Promise.all([request(`/messages?folder=${nextFolder}&q=${encodeURIComponent(nextQuery)}`, {}, token), request('/me', {}, token)])
    setMessages(list.messages)
    setStats(me.stats)
    if (!list.messages.some((item) => item.id === selectedId)) {
      setSelectedId(null)
      setSelected(null)
    }
  }

  useEffect(() => {
    if (!token) return
    refresh().catch(() => { sessionStorage.removeItem('wpyw-token'); setToken(null) })
  }, [token, folder])

  async function selectMessage(id) {
    setSelectedId(id)
    const data = await request(`/messages/${id}`, {}, token)
    setSelected(data.message)
    setMessages((items) => items.map((item) => item.id === id ? { ...item, unread: false } : item))
    setStats((value) => ({ ...value, unread: Math.max(0, value.unread - 1) }))
  }

  function login(data) {
    sessionStorage.setItem('wpyw-token', data.token)
    setToken(data.token)
    setUser(data.user)
  }

  async function logout() {
    await request('/logout', { method: 'POST' }, token).catch(() => {})
    sessionStorage.removeItem('wpyw-token')
    setToken(null)
  }

  if (!token) return <Login onLogin={login} />

  return <div className="app-shell"><Sidebar folder={folder} setFolder={setFolder} stats={stats} onCompose={() => setCompose({})} onLogout={logout} mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} /><main className="mail-main"><header className="topbar"><button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)}><Menu size={19} /></button><div className="search-box"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && refresh(folder, query)} placeholder="搜索邮件" /></div><div className="topbar-actions"><div className="connection-state"><span className="status-dot" />安全连接</div><div className="account-chip"><CircleUserRound size={18} /><span>{user?.email || 'admin@wpyw.site'}</span><ChevronDown size={15} /></div></div></header><div className="content-grid"><section className="list-panel"><div className="list-header"><div><p className="eyebrow">MAILBOX</p><h1>{folders.find((item) => item.id === folder)?.label || '收件箱'}</h1></div><button className="icon-button"><MoreHorizontal size={18} /></button></div><div className="list-meta"><span>{messages.length} 封邮件</span><button onClick={() => refresh()}>刷新</button></div><div className="message-list">{messages.length ? messages.map((message) => <MessageRow key={message.id} message={message} selected={selectedId === message.id} onSelect={selectMessage} />) : <div className="list-empty"><div className="empty-icon"><Mail size={20} /></div><strong>这里还没有邮件</strong><span>新邮件到达后会显示在这里。</span></div>}</div></section><Reader message={selected || (selectedId ? selectedSummary : null)} onBack={() => { setSelectedId(null); setSelected(null) }} onCompose={(initial) => setCompose(initial)} /></div></main>{compose && <Compose initial={compose} token={token} onClose={() => setCompose(null)} onSent={() => { setCompose(null); refresh() }} />}</div>
}

export default App
