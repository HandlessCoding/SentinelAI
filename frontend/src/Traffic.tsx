import { Activity, Network, ShieldAlert, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type TrafficDetail, type TrafficFlow, type ZeekProtocol } from './api'
import { shortId, State, useResource } from './shared'

const PAGE_SIZE = 25
const protocols: Record<ZeekProtocol, string> = { tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', unknown_transport: 'Unknown transport' }
const labels = { benign: 'Reviewed benign', attack: 'Reviewed attack', unknown: 'Unknown' }
const show = (value: string | number | null) => value ?? 'Unavailable'

function endpoint(host: string | null, port: number | null) {
  if (host === null) return port === null ? 'Unavailable' : `Port ${port}`
  if (port === null) return host
  return `${host.includes(':') ? '[' + host + ']' : host}:${port}`
}

function TrafficTable({ flows }: { flows: TrafficFlow[] }) {
  return <div className="table-scroll" role="region" aria-label="Flow table" tabIndex={0}><table>
    <thead><tr><th>First packet (UTC)</th><th>Originator</th><th>Responder</th><th>Protocol</th><th>State</th>
      <th>Ground truth</th><th>Rule finding</th></tr></thead>
    <tbody>{flows.map(flow => <tr key={flow.id}>
      <td><a href={'#traffic/' + flow.id} aria-label={'View flow ' + shortId(flow.id)}><time dateTime={flow.observed_at}>
        {flow.observed_at.replace('T', ' ').slice(0, 19)}</time></a></td>
      <td>{endpoint(flow.orig_host, flow.orig_port)}</td><td>{endpoint(flow.resp_host, flow.resp_port)}</td>
      <td>{protocols[flow.proto]}</td><td>{show(flow.conn_state)}</td><td>{labels[flow.ground_truth]}</td>
      <td>{flow.finding ? <span className="traffic-finding">Review</span> : 'None'}</td>
    </tr>)}</tbody>
  </table></div>
}

function Details({ flow }: { flow: TrafficDetail }) {
  const facts = [
    ['Observed at (UTC)', flow.observed_at], ['Protocol', protocols[flow.proto]],
    ['Originator', endpoint(flow.orig_host, flow.orig_port)], ['Responder', endpoint(flow.resp_host, flow.resp_port)],
    ['Connection state', flow.conn_state], ['Service', flow.service], ['Duration (ns)', flow.duration_ns],
    ['Zeek history', flow.history], ['Originator packets', flow.orig_pkts], ['Responder packets', flow.resp_pkts],
    ['Originator IP bytes', flow.orig_ip_bytes], ['Responder IP bytes', flow.resp_ip_bytes],
    ['Originator payload bytes', flow.orig_bytes], ['Responder payload bytes', flow.resp_bytes],
    ['Missed payload bytes', flow.missed_bytes], ['Capture', flow.capture_id], ['Source row', flow.source_row],
    ['Session', flow.capture.session_id], ['Environment', flow.capture.environment_id],
    ['Observation point', flow.capture.observation_point],
    ['Capture source', flow.capture.source === 'authorized_lab' ? 'Authorized lab' : 'Authorized archive'],
    ['Zeek version', flow.capture.zeek_version], ['Imported at', flow.capture.imported_at],
    ['Connection log SHA-256', flow.capture.conn_sha256], ['PCAP SHA-256', flow.capture.pcap_sha256],
    ['Manifest SHA-256', flow.capture.manifest_sha256],
  ] as const
  return <div className="detail-content traffic-detail">
    <section><h3>Evidence and triage</h3>
      <p><strong>Ground truth</strong> {labels[flow.ground_truth]}{flow.label_category && ` (${flow.label_category})`}</p>
      <p><strong>Label reason</strong> {flow.label_reason.replaceAll('_', ' ')}</p>
      <p><strong>Rule finding</strong> {flow.finding ? flow.finding.explanation : 'None'}</p>
      {flow.finding && <p><code>{flow.finding.code}</code></p>}
    </section>
    <dl className="facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{show(value)}</dd></div>)}</dl>
  </div>
}

export function Traffic({ selected, revision, refresh }: { selected?: string; revision: number; refresh: () => void }) {
  const [filters, setFilters] = useState({ protocol: '', capture_id: '', has_finding: '' })
  const [offset, setOffset] = useState(0)
  const close = useRef<HTMLAnchorElement>(null)
  const summary = useResource(useCallback((signal: AbortSignal) => api.trafficSummary(signal), [revision]))
  const page = useResource(useCallback((signal: AbortSignal) => {
    const query = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) })
    for (const [name, value] of Object.entries(filters)) if (value) query.set(name, value)
    return api.trafficFlows(query, signal)
  }, [filters, offset, revision]))
  const loadDetail = useCallback((signal: AbortSignal) => api.trafficFlow(selected!, signal), [selected, revision])
  const details = useResource(selected ? loadDetail : null)

  useEffect(() => { if (selected) close.current?.focus() }, [selected])

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setOffset(0)
    setFilters({ protocol: String(fields.get('protocol')), capture_id: String(fields.get('capture_id')).trim(),
      has_finding: String(fields.get('has_finding')) })
  }

  return <>
    {summary.loading && <div className="panel"><State kind="loading" title="Loading traffic summary" /></div>}
    {summary.error && <div className="panel"><State kind="error" title="Could not load traffic summary" detail={summary.error}>
      <button className="button secondary" onClick={refresh}>Retry summary</button>
    </State></div>}
    {summary.value && <div className="metrics traffic-metrics">
      <article className="panel metric"><div className="metric-top"><span>Imported flows</span><Activity size={18} /></div>
        <strong>{summary.value.total_flows.toLocaleString()}</strong><small>Recorded offline</small></article>
      <article className="panel metric"><div className="metric-top"><span>Rule findings</span><ShieldAlert size={18} /></div>
        <strong>{summary.value.finding_count.toLocaleString()}</strong><small>Connection signals for review</small></article>
      <article className="panel metric"><div className="metric-top"><span>Protocol breakdown</span><Network size={18} /></div>
        {summary.value.protocols.length ? <ul className="traffic-protocols">{summary.value.protocols.map(({ protocol, count }) =>
          <li key={protocol}><span>{protocols[protocol]}</span><b>{count.toLocaleString()}</b></li>)}</ul> : <small>No imported protocols</small>}
      </article>
    </div>}
    <section className="panel">
      <div className="panel-heading"><div><h2>Recorded connections</h2><p>Ground truth comes from reviewed capture evidence.</p></div></div>
      <form className="filters" onSubmit={applyFilters}>
        <label className="filter"><select name="protocol" aria-label="Filter by protocol">
          <option value="">All protocols</option>{Object.entries(protocols).map(([key, name]) => <option key={key} value={key}>{name}</option>)}
        </select></label>
        <label className="search"><input name="capture_id" aria-label="Filter by capture ID" placeholder="Capture ID" maxLength={64}
          pattern="[a-z0-9][a-z0-9_\-]{0,63}" /></label>
        <label className="filter"><select name="has_finding" aria-label="Filter by rule finding"><option value="">All flows</option>
          <option value="true">With findings</option><option value="false">Without findings</option></select></label>
        <button className="button secondary" type="submit">Apply filters</button>
      </form>
      {page.loading && <State kind="loading" title="Loading flows" />}
      {page.error && <State kind="error" title="Could not load flows" detail={page.error}>
        <button className="button secondary" onClick={refresh}>Retry flows</button>
      </State>}
      {page.value && (page.value.flows.length ? <TrafficTable flows={page.value.flows} /> :
        <State title="No flows to show" detail={summary.value?.total_flows === 0 ? 'Import a reviewed Zeek capture to get started.' : 'Try a different filter.'} />)}
      {page.value && (offset > 0 || page.value.next_offset !== null) && <div className="panel-heading">
        <button className="button secondary" disabled={offset === 0} onClick={() => setOffset(offset - PAGE_SIZE)}>Previous</button>
        <button className="button secondary" disabled={page.value.next_offset === null}
          onClick={() => setOffset(page.value?.next_offset ?? offset)}>Next</button>
      </div>}
    </section>
    {selected && <aside className="detail-pane" aria-label="Flow details" onKeyDown={event => {
      if (event.key === 'Escape') window.location.hash = 'traffic'
    }}>
      <div className="panel-heading"><h2>Flow details</h2><a ref={close} className="icon-button" href="#traffic" aria-label="Close flow details"><X size={20} /></a></div>
      {details.loading && <State kind="loading" title="Loading flow details" />}
      {details.error && <State kind="error" title="Could not load flow" detail={details.error} />}
      {details.value && <Details flow={details.value} />}
    </aside>}
  </>
}
