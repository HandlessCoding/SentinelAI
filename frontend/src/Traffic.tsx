import { Activity, Network, ShieldAlert, X } from 'lucide-react'
import { useCallback, useRef, useState, type FormEvent } from 'react'
import { api, type TrafficDetail, type TrafficFlow, type TrafficMonitoring, type TrafficSource, type ZeekProtocol } from './api'
import { dateTime, shortId, State, useDetailFocus, useResource } from './shared'

const PAGE_SIZE = 25
export const TRAFFIC_POLL_MS = 5000
const protocols: Record<ZeekProtocol, string> = { tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', unknown_transport: 'Unknown transport' }
const sources: Record<TrafficSource, string> = {
  authorized_lab: 'Offline lab capture', authorized_archive: 'Offline archive',
  recorded_replay: 'Recorded replay', connected_sensor: 'Connected sensor',
}
const labels = { benign: 'Reviewed benign', attack: 'Reviewed attack', unknown: 'Unknown' }
const show = (value: string | number | null) => value ?? 'Unavailable'
const showTime = (value: string | null) => value ? dateTime(value) : 'Never'
const ingestionStatus = { ready: 'Reading', waiting: 'Waiting for source', blocked: 'Checkpoint blocked',
  stale: 'Worker heartbeat missing', starting: 'Starting' }

function endpoint(host: string | null, port: number | null) {
  if (host === null) return port === null ? 'Unavailable' : `Port ${port}`
  if (port === null) return host
  return `${host.includes(':') ? '[' + host + ']' : host}:${port}`
}

const firstPacketLabel = (observedAt: string) => observedAt.replace('T', ' ').slice(0, 19)

function TrafficTable({ flows }: { flows: TrafficFlow[] }) {
  return <div className="table-scroll" role="region" aria-label="Flow table" tabIndex={0}><table>
    <thead><tr><th>First packet (UTC)</th><th>Originator</th><th>Responder</th><th>Protocol</th><th>State</th>
      <th>Input kind</th><th>Reviewed ground truth</th><th>Rule finding</th></tr></thead>
    <tbody>{flows.map(flow => <tr key={flow.id}>
      <td><a href={'#traffic/' + flow.id} aria-label={`${firstPacketLabel(flow.observed_at)} UTC, view flow ${shortId(flow.id)}`}><time dateTime={flow.observed_at}>
        {firstPacketLabel(flow.observed_at)}</time></a></td>
      <td>{endpoint(flow.orig_host, flow.orig_port)}</td><td>{endpoint(flow.resp_host, flow.resp_port)}</td>
      <td>{protocols[flow.proto]}</td><td>{show(flow.conn_state)}</td><td>{sources[flow.source]}</td>
      <td>{labels[flow.ground_truth]}</td>
      <td>{flow.finding ? <span className="traffic-finding">Review</span> : 'None'}</td>
    </tr>)}</tbody>
  </table></div>
}

function Details({ flow }: { flow: TrafficDetail }) {
  const continuous = flow.source === 'recorded_replay' || flow.source === 'connected_sensor'
  const facts = [
    ['Observed at (UTC)', flow.observed_at], ['Protocol', protocols[flow.proto]],
    ['Originator', endpoint(flow.orig_host, flow.orig_port)], ['Responder', endpoint(flow.resp_host, flow.resp_port)],
    ['Connection state', flow.conn_state], ['Service', flow.service], ['Duration (ns)', flow.duration_ns],
    ['Zeek history', flow.history], ['Originator packets', flow.orig_pkts], ['Responder packets', flow.resp_pkts],
    ['Originator IP bytes', flow.orig_ip_bytes], ['Responder IP bytes', flow.resp_ip_bytes],
    ['Originator payload bytes', flow.orig_bytes], ['Responder payload bytes', flow.resp_bytes],
    ['Missed payload bytes', flow.missed_bytes], [continuous ? 'Ingestion source ID' : 'Capture ID', flow.capture_id],
    ['Source row', flow.source_row], ['Session', flow.capture.session_id], ['Recorded environment ID', flow.capture.environment_id],
    ['Observation point', flow.capture.observation_point],
    ['Input kind', sources[flow.capture.source]], ['Zeek version', flow.capture.zeek_version],
    [continuous ? 'Source registered at' : 'Imported at', flow.capture.imported_at],
    ['Connection log SHA-256', flow.capture.conn_sha256], ['PCAP SHA-256', flow.capture.pcap_sha256],
    [continuous ? 'Source configuration SHA-256' : 'Manifest SHA-256', flow.capture.manifest_sha256],
    ...(flow.ingested_at ? [['Ingested at', flow.ingested_at], ['File identity', flow.source_file],
      ['Byte offset', flow.source_offset]] as const : []),
  ] as const
  return <div className="detail-content traffic-detail">
    <section><h3>Evidence and triage</h3>
      <p><strong>Reviewed ground truth</strong> {labels[flow.ground_truth]}{flow.label_category && ` (${flow.label_category})`}</p>
      <p><strong>Label reason</strong> {flow.label_reason.replaceAll('_', ' ')}</p>
      <p><strong>Rule finding</strong> {flow.finding ? flow.finding.explanation : 'None'}</p>
      {flow.finding && <p><code>{flow.finding.code}</code></p>}
    </section>
    <dl className="facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{show(value)}</dd></div>)}</dl>
  </div>
}

function Monitoring({ summary }: { summary: TrafficMonitoring }) {
  return <section className="panel">
    <div className="panel-heading"><div><h2>Continuous ingestion</h2>
      <p>{summary.recent_flows.toLocaleString()} flows and {summary.recent_findings.toLocaleString()} rule findings in the last 5 minutes</p>
      {summary.protocols.length > 0 && <p>{summary.protocols.map(({ protocol, count }) =>
        protocols[protocol] + ' ' + count.toLocaleString()).join(' · ')}</p>}</div></div>
    {summary.sources.length === 0 ? <State title="No ingestion source registered" /> :
      <div className="table-scroll" role="region" aria-label="Ingestion source health" tabIndex={0}><table>
        <thead><tr><th>Ingestion source</th><th>Health</th><th>Processing lag</th><th>Errors</th>
          <th>Last successful update</th><th>Last flow ingested</th></tr></thead>
        <tbody>{summary.sources.map(source => <tr key={source.capture_id}>
          <td><strong>{source.capture_id}</strong><br />{sources[source.source]}
            {source.replay_capture_id && <><br />Original capture ID {source.replay_capture_id}</>}</td>
          <td>{ingestionStatus[source.status]}</td>
          <td>{source.backlog_bytes === null ? 'Unavailable' : source.backlog_bytes.toLocaleString() + ' bytes pending'}</td>
          <td>{source.rejected_rows.toLocaleString()} rejected · {source.duplicate_rows.toLocaleString()} duplicates
            {source.last_error && <><br />{source.last_error.replaceAll('_', ' ')}</>}</td>
          <td>{showTime(source.last_success_at)}</td><td>{showTime(source.last_ingested_at)}</td>
        </tr>)}</tbody>
      </table></div>}
    {summary.more_sources && <p>Showing the first 100 sources.</p>}
  </section>
}

export function Traffic({ selected, revision, refresh }: { selected?: string; revision: number; refresh: () => void }) {
  const [filters, setFilters] = useState({ protocol: '', capture_id: '', has_finding: '', source: '', order: '' })
  const [pages, setPages] = useState<{ cursor: string | null; previous: string[] }>({ cursor: null, previous: [] })
  const { cursor, previous } = pages
  const close = useRef<HTMLAnchorElement>(null)
  const protocolFilter = useRef<HTMLSelectElement>(null)
  const summary = useResource(useCallback((signal: AbortSignal) => api.trafficSummary(signal), [revision]))
  const monitoring = useResource(useCallback((signal: AbortSignal) => api.trafficMonitoring(signal), [revision]), TRAFFIC_POLL_MS)
  const page = useResource(useCallback((signal: AbortSignal) => {
    const query = new URLSearchParams({ limit: String(PAGE_SIZE), pagination: 'cursor' })
    if (cursor) query.set('cursor', cursor)
    for (const [name, value] of Object.entries(filters)) if (value) query.set(name, value)
    return api.trafficFlows(query, signal)
  }, [filters, cursor, revision]), cursor === null ? TRAFFIC_POLL_MS : undefined)
  const loadDetail = useCallback((signal: AbortSignal) => api.trafficFlow(selected!, signal), [selected, revision])
  const details = useResource(selected ? loadDetail : null)

  useDetailFocus(selected, close, protocolFilter)

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setPages({ cursor: null, previous: [] })
    setFilters({ protocol: String(fields.get('protocol')), capture_id: String(fields.get('capture_id')).trim(),
      has_finding: String(fields.get('has_finding')), source: String(fields.get('source')), order: String(fields.get('order')) })
  }

  return <>
    {summary.loading && <div className="panel"><State kind="loading" title="Loading traffic summary" /></div>}
    {summary.error && <div className="panel"><State kind="error" title="Could not load traffic summary" detail={summary.error}>
      <button className="button secondary" onClick={refresh}>Retry summary</button>
    </State></div>}
    {summary.value && <div className="metrics traffic-metrics">
      <article className="panel metric"><div className="metric-top"><span>Stored flows</span><Activity size={18} /></div>
        <strong>{summary.value.total_flows.toLocaleString()}</strong><small>All-time total at last refresh</small></article>
      <article className="panel metric"><div className="metric-top"><span>Rule findings</span><ShieldAlert size={18} /></div>
        <strong>{summary.value.finding_count.toLocaleString()}</strong><small>Connection signals for review</small></article>
      <article className="panel metric"><div className="metric-top"><span>Protocol breakdown</span><Network size={18} /></div>
        {summary.value.protocols.length ? <ul className="traffic-protocols">{summary.value.protocols.map(({ protocol, count }) =>
          <li key={protocol}><span>{protocols[protocol]}</span><b>{count.toLocaleString()}</b></li>)}</ul> : <small>No observed protocols</small>}
      </article>
    </div>}
    {monitoring.loading && <div className="panel"><State kind="loading" title="Loading ingestion health" /></div>}
    {monitoring.error && <div className="panel"><State kind="error" title="Could not load ingestion health" detail={monitoring.error}>
      <button className="button secondary" onClick={refresh}>Retry ingestion health</button>
    </State></div>}
    {monitoring.value && <Monitoring summary={monitoring.value} />}
    <section className="panel">
      <div className="panel-heading"><div><h2>Connections</h2><p>Reviewed ground truth comes from capture evidence.</p></div></div>
      <form className="filters" onSubmit={applyFilters}>
        <label className="filter"><select ref={protocolFilter} name="protocol" aria-label="Filter by protocol">
          <option value="">All protocols</option>{Object.entries(protocols).map(([key, name]) => <option key={key} value={key}>{name}</option>)}
        </select></label>
        <label className="search"><input name="capture_id" aria-label="Filter by capture or ingestion source ID" placeholder="Capture or source ID" maxLength={64}
          pattern="[a-z0-9][a-z0-9_\-]{0,63}" /></label>
        <label className="filter"><select name="has_finding" aria-label="Filter by rule finding"><option value="">All flows</option>
          <option value="true">With findings</option><option value="false">Without findings</option></select></label>
        <label className="filter"><select name="source" aria-label="Filter by input kind"><option value="">All input kinds</option>
          {Object.entries(sources).map(([key, name]) => <option key={key} value={key}>{name}</option>)}</select></label>
        <label className="filter"><select name="order" aria-label="Sort connections"><option value="">Latest observed</option>
          <option value="ingested">Recently ingested</option></select></label>
        <button className="button secondary" type="submit">Apply filters</button>
      </form>
      {page.loading && <State kind="loading" title="Loading flows" />}
      {page.error && <State kind="error" title="Could not load flows" detail={page.error}>
        <button className="button secondary" onClick={refresh}>Retry flows</button>
      </State>}
      {page.value && (page.value.flows.length ? <TrafficTable flows={page.value.flows} /> :
        <State title="No flows to show" detail={summary.value?.total_flows === 0 ? 'Import a reviewed Zeek capture to get started.' : 'Try a different filter.'} />)}
      {(cursor !== null || page.value?.next_cursor) && <div className="panel-heading">
        <button className="button secondary" disabled={previous.length === 0}
          onClick={() => setPages({ cursor: previous.at(-1) ?? null, previous: previous.slice(0, -1) })}>Previous</button>
        <button className="button secondary" disabled={!page.value?.next_cursor}
          onClick={() => {
            if (page.value?.next_cursor) setPages({ cursor: page.value.next_cursor, previous: [...previous, page.value.page_cursor] })
          }}>Next</button>
        {cursor !== null && <button className="button secondary" onClick={() => setPages({ cursor: null, previous: [] })}>Resume live</button>}
      </div>}
    </section>
    {selected && <aside className="detail-pane" aria-label="Flow details" onKeyDown={event => {
      if (event.key === 'Escape') window.location.hash = 'traffic'
    }}>
      <div className="panel-heading"><h2>Flow details</h2><a ref={close} className="icon-button" href="#traffic" aria-label="Close flow details"><X size={20} /></a></div>
      {details.loading && <State kind="loading" title="Loading flow details" />}
      {details.error && <State kind="error" title="Could not load flow" detail={details.error}>
        <button className="button secondary" onClick={refresh}>Retry flow details</button>
      </State>}
      {details.value && <Details flow={details.value} />}
    </aside>}
  </>
}
