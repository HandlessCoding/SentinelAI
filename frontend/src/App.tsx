import {
  Activity, FileSearch, LayoutDashboard, Menu, NotebookPen, RefreshCw,
  Network, ScanLine, Server, Shield, ShieldAlert, X,
} from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from 'react'
import { Analyze } from './Analyze'
import { Alerts, Overview } from './Alerts'
import { Investigations } from './Investigations'
import { api } from './api'
import { State, useResource } from './shared'
import { Traffic } from './Traffic'

const pages = {
  overview: { label: 'Overview', icon: LayoutDashboard, title: 'Security overview', detail: 'Track model detections and the investigations they lead to.' },
  alerts: { label: 'Alerts', icon: ShieldAlert, title: 'Alerts', detail: 'Review and triage suspected attacks from saved analyses.' },
  traffic: { label: 'Network Traffic', icon: Network, title: 'Network traffic', detail: 'Inspect Zeek flows, source health, reviewed labels, and rule findings.' },
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
  const main = useRef<HTMLElement>(null)
  const openNavigation = useRef<HTMLButtonElement>(null)
  const sidebar = useRef<HTMLElement>(null)
  const restoreMenuFocus = useRef(false)
  const previousPage = useRef(page)
  const refresh = useCallback(() => setRevision(value => value + 1), [])

  const closeMenu = useCallback((restoreFocus = true) => {
    restoreMenuFocus.current = restoreFocus
    setMenuOpen(false)
  }, [])

  useEffect(() => {
    function updateRoute() {
      setRoute(readRoute())
      closeMenu(false)
    }
    window.addEventListener('hashchange', updateRoute)
    return () => window.removeEventListener('hashchange', updateRoute)
  }, [closeMenu])

  useEffect(() => {
    if (page !== previousPage.current && !(page === 'alerts' && selected)) main.current?.focus()
    previousPage.current = page
  }, [page, selected])

  useEffect(() => {
    if (!menuOpen) {
      if (restoreMenuFocus.current) openNavigation.current?.focus()
      restoreMenuFocus.current = false
      return
    }
    sidebar.current?.querySelector<HTMLElement>('nav a[aria-current="page"]')?.focus()
    const mobile = window.matchMedia?.('(max-width: 790px)')
    const closeOnDesktop = (event: MediaQueryListEvent) => {
      if (!event.matches) closeMenu(false)
    }
    mobile?.addEventListener('change', closeOnDesktop)
    return () => mobile?.removeEventListener('change', closeOnDesktop)
  }, [menuOpen, closeMenu])

  function handleMenuKeys(event: KeyboardEvent<HTMLElement>) {
    if (!menuOpen || event.defaultPrevented) return
    if (event.key === 'Escape') {
      event.preventDefault()
      closeMenu()
    } else if (event.key === 'Tab') {
      const first = sidebar.current?.querySelector<HTMLElement>('.brand')
      const last = sidebar.current?.querySelector<HTMLElement>('nav a:last-child')
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
  }

  useEffect(() => {
    const controller = new AbortController()
    let checking = false
    async function check() {
      if (checking) return
      checking = true
      try {
        await api.health(controller.signal)
        if (!controller.signal.aborted) setConnection('online')
      } catch {
        if (!controller.signal.aborted) setConnection('offline')
      } finally {
        checking = false
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
  const loadAlerts = useCallback((signal: AbortSignal) => api.alerts(signal), [revision])
  const alerts = useResource(page === 'traffic' ? null : loadAlerts)
  const current = pages[page]

  return <div className="shell">
    {!menuOpen && <a className="skip-link" href="#main-content" onClick={event => {
      event.preventDefault()
      main.current?.focus()
    }}>Skip to main content</a>}
    {menuOpen && <div className="mobile-overlay" onClick={() => closeMenu()} aria-hidden="true" />}
    <aside className={'sidebar' + (menuOpen ? ' mobile-open' : '')} id="workspace-sidebar" ref={sidebar}
      role={menuOpen ? 'dialog' : undefined} aria-label={menuOpen ? 'Workspace navigation' : undefined}
      aria-modal={menuOpen ? true : undefined} onKeyDown={handleMenuKeys}>
      <a className="brand" href="#overview" onClick={() => closeMenu(page === 'overview')}><span className="brand-icon"><Shield size={23} /></span><span>Sentinel<span>AI</span><small>Security Operations</small></span></a>
      <button className="icon-button sidebar-close" aria-label="Close menu" onClick={() => closeMenu()}><X size={18} /></button>
      <nav aria-label="Workspace">
        {pageList.map(name => {
          const { icon: Icon, label } = pages[name]
          return <a key={name} className={page === name ? 'active' : ''} href={'#' + name} aria-current={page === name ? 'page' : undefined}
            onClick={() => closeMenu(page === name)}><Icon size={19} /><span>{label}</span></a>
        })}
      </nav>
      <div className="sidebar-footer"><div className="server-icon"><Server size={18} /></div><div><strong>Local workspace</strong>
        <small>{model.value?.model_version ?? (model.loading ? 'Checking model…' : 'Model unavailable')}</small></div></div>
    </aside>
    <div className="workspace" inert={menuOpen}>
      <header className="topbar">
        <div><button className="icon-button mobile-menu" ref={openNavigation} onClick={() => setMenuOpen(true)}
          aria-label="Open navigation" aria-expanded={menuOpen} aria-controls="workspace-sidebar">
          {menuOpen ? <X size={22} /> : <Menu size={22} />}
        </button><Activity size={19} className="topbar-mark" /><span className="topbar-label">Operations</span><span className="topbar-divider">/</span><strong>{current.label}</strong></div>
        <span className={'connection connection-' + connection} role="status"><i />
          {connection === 'checking' ? 'Checking API' : connection === 'online' ? 'API connected' : 'API offline'}
        </span>
      </header>
      <main id="main-content" ref={main} tabIndex={-1}>
        <div className="page-heading">
          <div><h1>{current.title}</h1><p>{current.detail}</p></div>
          <div className="page-actions">
            <button className="button secondary" onClick={refresh}><RefreshCw size={17} />Refresh</button>
            {page !== 'analyze' && page !== 'traffic' && <a className="button primary" href="#analyze"><ScanLine size={17} />Analyze records</a>}
          </div>
        </div>
        {page === 'analyze' ? <Analyze model={model.value} refresh={refresh} /> : page === 'traffic' ?
          <Traffic selected={selected} revision={revision} refresh={refresh} /> : <>
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
