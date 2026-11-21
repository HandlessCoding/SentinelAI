import {
  Activity, FileSearch, LayoutDashboard, Menu, NotebookPen, RefreshCw,
  ScanLine, Server, Shield, ShieldAlert, X,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Analyze } from './Analyze'
import { Alerts, Overview } from './Alerts'
import { Investigations } from './Investigations'
import { api } from './api'
import { State, useResource } from './shared'

const pages = {
  overview: { label: 'Overview', icon: LayoutDashboard, title: 'Security overview', detail: 'Track model detections and the investigations they lead to.' },
  alerts: { label: 'Alerts', icon: ShieldAlert, title: 'Alerts', detail: 'Review and triage suspected attacks from saved analyses.' },
  incidents: { label: 'Incidents', icon: FileSearch, title: 'Incidents', detail: 'Open an investigation, link alerts, and update its status.' },
  notes: { label: 'Analyst Notes', icon: NotebookPen, title: 'Analyst notes', detail: 'Read and add notes within an investigation.' },
  analyze: { label: 'Analyze', icon: ScanLine, title: 'Analyze records', detail: 'Score prepared network records with the local Random Forest model.' },
}
type Page = keyof typeof pages
const pageList = Object.keys(pages) as Page[]

function readRoute() {
  const [path, selected, initialAlert] = window.location.hash.slice(1).split('/')
  const page: Page = pageList.includes(path as Page) ? path as Page : 'overview'
  return { page, selected, initialAlert }
}

export default function App() {
  const [{ page, selected, initialAlert }, setRoute] = useState(readRoute)
  const [revision, setRevision] = useState(0)
  const [menuOpen, setMenuOpen] = useState(false)
  const [connection, setConnection] = useState<'checking' | 'online' | 'offline'>('checking')
  const refresh = useCallback(() => setRevision(value => value + 1), [])

  useEffect(() => {
    function updateRoute() {
      setRoute(readRoute())
      setMenuOpen(false)
    }
    window.addEventListener('hashchange', updateRoute)
    return () => window.removeEventListener('hashchange', updateRoute)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    async function check() {
      try {
        await api.health(controller.signal)
        if (!controller.signal.aborted) setConnection('online')
      } catch {
        if (!controller.signal.aborted) setConnection('offline')
      }
    }
    void check()
    const timer = window.setInterval(check, 25000)
    return () => {
      controller.abort()
      window.clearInterval(timer)
    }
  }, [revision])

  const model = useResource(useCallback((signal: AbortSignal) => api.model(signal), [revision]))
  const alerts = useResource(useCallback((signal: AbortSignal) => api.alerts(signal), [revision]))
  const current = pages[page]

  return <div className="shell">
    {menuOpen && <button className="mobile-overlay" onClick={() => setMenuOpen(false)} aria-label="Close navigation" />}
    <aside className={'sidebar' + (menuOpen ? ' mobile-open' : '')}>
      <a className="brand" href="#overview"><span className="brand-icon"><Shield size={23} /></span><span>Sentinel<span>AI</span><small>Security Operations</small></span></a>
      <button className="icon-button sidebar-close" aria-label="Close menu" onClick={() => setMenuOpen(false)}><X size={18} /></button>
      <nav aria-label="Workspace">
        {pageList.map(name => {
          const { icon: Icon, label } = pages[name]
          return <a key={name} className={page === name ? 'active' : ''} href={'#' + name} aria-current={page === name ? 'page' : undefined}
            onClick={() => setMenuOpen(false)}><Icon size={19} /><span>{label}</span></a>
        })}
      </nav>
      <div className="sidebar-footer"><div className="server-icon"><Server size={18} /></div><div><strong>Local workspace</strong>
        <small>{model.value?.model_version ?? (model.loading ? 'Checking model…' : 'Model unavailable')}</small></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar">
        <div><button className="icon-button mobile-menu" onClick={() => setMenuOpen(value => !value)} aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen}>
          {menuOpen ? <X size={22} /> : <Menu size={22} />}
        </button><Activity size={19} className="topbar-mark" /><span className="topbar-label">Operations</span><span className="topbar-divider">/</span><strong>{current.label}</strong></div>
        <span className={'connection connection-' + connection} role="status"><i />
          {connection === 'checking' ? 'Checking API' : connection === 'online' ? 'API connected' : 'API offline'}
        </span>
      </header>
      <main id="main-content">
        <div className="page-heading">
          <div><h1>{current.title}</h1><p>{current.detail}</p></div>
          <div className="page-actions">
            <button className="button secondary" onClick={refresh}><RefreshCw size={17} />Refresh</button>
            {page !== 'analyze' && <a className="button primary" href="#analyze"><ScanLine size={17} />Analyze records</a>}
          </div>
        </div>
        {page === 'analyze' ? <Analyze model={model.value} refresh={refresh} /> : <>
          {alerts.loading && <div className="panel"><State kind="loading" title="Loading workspace data" /></div>}
          {alerts.error && <div className="panel"><State kind="error" title="Could not load alerts" detail={alerts.error}>
            <button className="button secondary" onClick={refresh}>Retry</button>
          </State></div>}
          {alerts.value && page === 'overview' && <Overview alerts={alerts.value} />}
          {alerts.value && page === 'alerts' && <Alerts alerts={alerts.value} selected={selected} revision={revision} />}
          {alerts.value && (page === 'incidents' || page === 'notes') &&
            <Investigations alerts={alerts.value} selected={selected} initialAlert={initialAlert} mode={page} change={refresh} revision={revision} />}
        </>}
      </main>
    </div>
  </div>
}
