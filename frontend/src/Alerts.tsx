import { Activity, Archive, BellRing, ChevronRight, CircleAlert, Filter, Search, ShieldAlert, X } from 'lucide-react'
import { useCallback, useState } from 'react'
import { api, incidentIds, type Alert, type AlertStatus } from './api'
import { dateTime, percentage, shortId, State, Status, statuses, useResource } from './shared'

export function AlertTable({ alerts }: { alerts: Alert[] }) {
  if (!alerts.length) return <State title="No alerts to show" />
  return <div className="table-scroll"><table>
    <thead><tr><th>Detection</th><th>Attack probability</th><th>Status</th><th>Detected</th><th aria-label="Details" /></tr></thead>
    <tbody>{alerts.map(alert => <tr key={alert.id}>
      <td><a className="alert-label" href={'#alerts/' + alert.id}>
        <span className="signal-icon"><ShieldAlert size={17} /></span>
        <span><strong>Suspected attack</strong><small>#{shortId(alert.id)}</small></span>
      </a></td>
      <td><div className="probability"><span className="probability-track"><span style={{ width: percentage(alert.attack_probability) }} /></span>
        <strong>{percentage(alert.attack_probability)}</strong></div></td>
      <td><Status status={alert.investigation_status} /></td>
      <td className="timestamp">{dateTime(alert.prediction_timestamp)}</td>
      <td><a className="icon-button detail-link" href={'#alerts/' + alert.id} aria-label={'View alert ' + shortId(alert.id)}><ChevronRight size={18} /></a></td>
    </tr>)}</tbody>
  </table></div>
}

function weekCounts(alerts: Alert[]) {
  const now = new Date()
  return Array.from({ length: 7 }, (_, index) => {
    const day = new Date(now.getFullYear(), now.getMonth(), now.getDate() + index - 6)
    const next = new Date(day.getFullYear(), day.getMonth(), day.getDate() + 1)
    return {
      label: day.toLocaleDateString(undefined, { weekday: 'short' }),
      full: day.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      count: alerts.filter(alert => {
        const timestamp = new Date(alert.prediction_timestamp)
        return day <= timestamp && timestamp < next
      }).length,
    }
  })
}

export function Overview({ alerts }: { alerts: Alert[] }) {
  const unreviewed = alerts.filter(alert => alert.investigation_status === 'unreviewed').length
  const active = incidentIds(alerts.filter(alert => alert.investigation_status !== 'resolved')).length
  const resolved = incidentIds(alerts.filter(alert => alert.investigation_status === 'resolved')).length
  const linked = alerts.length - unreviewed
  const reviewedShare = alerts.length ? linked / alerts.length : 0
  const days = weekCounts(alerts)
  const step = Math.max(1, Math.ceil(Math.max(...days.map(day => day.count)) / 4))
  const ceiling = step * 4
  const metrics = [
    { label: 'Total alerts', value: alerts.length, icon: BellRing, tone: 'cyan', caption: 'Persisted detections' },
    { label: 'Unreviewed alerts', value: unreviewed, icon: CircleAlert, tone: 'amber', caption: 'Awaiting an investigation' },
    { label: 'Active incidents', value: active, icon: Activity, tone: 'blue', caption: 'Open or investigating' },
    { label: 'Resolved incidents', value: resolved, icon: Archive, tone: 'green', caption: 'Closed investigations' },
  ]
  return <>
    <div className="metrics">{metrics.map(({ label, value, icon: Icon, tone, caption }) =>
      <article className="panel metric" key={label}>
        <div className="metric-top"><span>{label}</span><span className={'metric-icon tone-' + tone}><Icon size={18} /></span></div>
        <strong>{value.toLocaleString()}</strong><small>{caption}</small>
      </article>)}</div>
    <div className="chart-panels">
      <section className="panel trend">
        <div className="panel-heading"><div><h2>Detection activity</h2><p>Persisted alerts by day</p></div><span className="quiet-label">Last 7 days</span></div>
        <div className="chart" role="img" aria-label={'Alerts by day. ' + days.map(day => day.full + ': ' + day.count).join(', ')}>
          <div className="chart-axis">{[4, 3, 2, 1, 0].map(level => <span key={level}>{level * step}</span>)}</div>
          <div className="chart-plot">
            <div className="chart-bars">{days.map(day => <div key={day.full} className="bar-slot" title={day.full + ': ' + day.count + ' alerts'}>
              <span className="bar" style={{ height: ((day.count / ceiling) * 100) + '%' }} />
            </div>)}</div>
            <div className="chart-labels">{days.map(day => <span key={day.full}>{day.label}</span>)}</div>
          </div>
        </div>
      </section>
      <section className="panel queue">
        <div className="panel-heading"><div><h2>Alert breakdown</h2><p>Investigation coverage</p></div></div>
        <div className="ring-layout">
          <div className="ring" aria-label={linked + ' linked alerts and ' + unreviewed + ' unreviewed alerts'} role="img"
            style={alerts.length ? { background: `conic-gradient(#4bdcca 0 ${reviewedShare * 100}%, #dca45b 0 100%)` } : undefined}>
            <div><strong>{alerts.length.toLocaleString()}</strong><span>Alerts</span></div>
          </div>
          <div className="legend">
            <div><span><i />Linked to incident</span><strong>{linked}</strong></div>
            <div><span><i />Unreviewed</span><strong>{unreviewed}</strong></div>
          </div>
        </div>
      </section>
    </div>
    <section className="panel">
      <div className="panel-heading"><div><h2>Recent alerts</h2><p>Latest suspected attacks from the local workspace</p></div><a className="button secondary" href="#alerts">View alerts</a></div>
      <AlertTable alerts={alerts.slice(0, 5)} />
    </section>
  </>
}

export function Alerts({ alerts, selected, revision }: { alerts: Alert[]; selected?: string; revision: number }) {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<AlertStatus | ''>('')
  const [minimum, setMinimum] = useState('')
  const loadDetail = useCallback((signal: AbortSignal) => api.alert(selected!, signal), [selected, revision])
  const detail = useResource(selected ? loadDetail : null)
  const search = query.trim().toLowerCase()
  const filtered = alerts.filter(alert => {
    const terms = [alert.id, alert.batch_id, alert.model_version, 'suspected attack', statuses[alert.investigation_status]]
    return (!status || status === alert.investigation_status) &&
      (!minimum || alert.attack_probability >= Number(minimum)) &&
      terms.some(term => term.toLowerCase().includes(search))
  })
  return <section className="panel">
    <div className="panel-heading"><div><h2>Alert queue</h2><p>{filtered.length} of {alerts.length} alerts</p></div></div>
    <div className="filters">
      <label className="search"><Search size={18} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search ID, batch, model…" aria-label="Search alerts" /></label>
      <label className="filter"><Filter size={16} /><select aria-label="Filter by status" value={status} onChange={event => setStatus(event.target.value as AlertStatus | '')}>
        <option value="">All statuses</option>
        {Object.entries(statuses).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select></label>
      <label className="filter"><select aria-label="Minimum probability" value={minimum} onChange={event => setMinimum(event.target.value)}>
        <option value="">Any probability</option><option value="0.7">70% and above</option><option value="0.85">85% and above</option><option value="0.95">95% and above</option>
      </select></label>
    </div>
    <AlertTable alerts={filtered} />
    {selected && <aside className="detail-pane" aria-label="Alert details">
      <div className="panel-heading"><div><h2>Alert details</h2><p>#{shortId(selected)}</p></div><a className="icon-button" href="#alerts" aria-label="Close alert details"><X size={20} /></a></div>
      {detail.loading && <State kind="loading" title="Loading alert" />}
      {detail.error && <State kind="error" title="Could not load alert" detail={detail.error} />}
      {detail.value && <div className="detail-content">
        <div className="detail-summary"><span className="signal-icon"><ShieldAlert size={22} /></span><div><h3>Suspected attack</h3><Status status={detail.value.investigation_status} /></div></div>
        <dl className="facts">
          <div><dt>Attack probability</dt><dd>{percentage(detail.value.attack_probability)}</dd></div>
          <div><dt>Detected</dt><dd>{dateTime(detail.value.prediction_timestamp)}</dd></div>
          <div><dt>Model</dt><dd>{detail.value.model_version}</dd></div>
          <div><dt>Record index</dt><dd>{detail.value.record_index}</dd></div>
          <div><dt>Batch ID</dt><dd className="mono">{detail.value.batch_id}</dd></div>
          <div><dt>Alert ID</dt><dd className="mono">{detail.value.id}</dd></div>
        </dl>
        <a className="button primary" href={detail.value.incident_id ? '#incidents/' + detail.value.incident_id : '#incidents/new/' + detail.value.id}>
          {detail.value.incident_id ? 'View investigation' : 'Create investigation'}
        </a>
      </div>}
    </aside>}
  </section>
}
