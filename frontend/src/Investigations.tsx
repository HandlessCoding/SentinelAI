import { ClipboardList, FileSearch, MessageSquarePlus, Plus } from 'lucide-react'
import { useCallback, useState, type FormEvent } from 'react'
import { api, incidentIds, type Alert, type Incident, type IncidentStatus } from './api'
import { dateTime, message, percentage, shortId, State, Status, statuses, useResource } from './shared'

function IncidentForm({ unassigned, initialAlert, incident, change }: {
  unassigned: Alert[]; initialAlert?: string; incident?: Incident; change: () => void
}) {
  const [title, setTitle] = useState(incident?.title ?? '')
  const [description, setDescription] = useState(incident?.description ?? '')
  const [status, setStatus] = useState<IncidentStatus>(incident?.status ?? 'open')
  const [selected, setSelected] = useState(() => unassigned.some(alert => alert.id === initialAlert) ? [initialAlert!] : [])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!title.trim() || (!incident && !selected.length)) {
      setError('Provide a title and select at least one alert for a new incident.')
      return
    }
    const details = { title: title.trim(), description: description.trim() || null }
    setBusy(true)
    setSaved(false)
    setError('')
    try {
      if (incident) {
        await api.updateIncident(incident.id, { ...details, status })
        setSaved(true)
      } else {
        const result = await api.createIncident({ ...details, alert_ids: selected })
        window.location.hash = 'incidents/' + result.id
      }
      change()
    } catch (error) {
      setError(message(error))
    } finally {
      setBusy(false)
    }
  }

  return <form className="field-stack" onSubmit={save}>
    <label>Title<input value={title} onChange={event => setTitle(event.target.value)} maxLength={160} required /></label>
    <label>Description<textarea value={description} onChange={event => setDescription(event.target.value)} maxLength={4000} rows={3} placeholder="Add investigation context" /></label>
    {incident ? <label>Status<select value={status} onChange={event => setStatus(event.target.value as IncidentStatus)}>
      {(['open', 'investigating', 'resolved'] as const).map(key => <option value={key} key={key}>{statuses[key]}</option>)}
    </select></label> : <fieldset>
      <legend>Link unassigned alerts</legend>
      {unassigned.length ? <div className="alert-picker">{unassigned.map(alert => <label key={alert.id} className="pick-row">
        <input type="checkbox" checked={selected.includes(alert.id)}
          disabled={selected.length >= 100 && !selected.includes(alert.id)}
          onChange={event => setSelected(values => event.target.checked ? [...values, alert.id] : values.filter(id => id !== alert.id))} />
        <span>Suspected attack <small>#{shortId(alert.id)}</small></span>
        <strong>{percentage(alert.attack_probability)}</strong>
      </label>)}</div> : <p className="muted">No unassigned alerts are available.</p>}
    </fieldset>}
    {error && <p className="inline-error" role="alert">{error}</p>}
    {saved && <p className="success" role="status">Incident updated.</p>}
    <button className="button primary" disabled={busy || (!incident && !unassigned.length)}>
      {busy ? 'Saving…' : incident ? 'Save changes' : 'Create incident'}
    </button>
  </form>
}

function NotePanel({ incident, change }: { incident: Incident; change: () => void }) {
  const [author, setAuthor] = useState('')
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function addNote(event: FormEvent) {
    event.preventDefault()
    if (!author.trim() || !text.trim()) {
      setError('An analyst name and note are required.')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.addNote(incident.id, { author: author.trim(), text: text.trim() })
      setText('')
      change()
    } catch (error) {
      setError(message(error))
    } finally {
      setBusy(false)
    }
  }

  return <>
    {incident.notes.length ? <ul className="notes">{incident.notes.map(note =>
      <li key={note.id}><span className="note-avatar">{note.author.slice(0, 2).toUpperCase()}</span>
        <div><strong>{note.author}</strong><time dateTime={note.created_at}>{dateTime(note.created_at)}</time><p>{note.text}</p></div>
      </li>)}</ul> : <State title="No notes yet" detail="Add the first note for this investigation." />}
    <form className="field-stack note-form" onSubmit={addNote}>
      <label>Analyst name<input required maxLength={80} value={author} onChange={event => setAuthor(event.target.value)} /></label>
      <label>Investigation note<textarea required maxLength={4000} rows={4} value={text} onChange={event => setText(event.target.value)} /></label>
      {error && <p className="inline-error" role="alert">{error}</p>}
      <button className="button primary" disabled={busy}><MessageSquarePlus size={17} />{busy ? 'Adding…' : 'Add note'}</button>
    </form>
  </>
}

export function Investigations({ alerts, selected, initialAlert, mode, revision, change }: {
  alerts: Alert[]; selected?: string; initialAlert?: string; mode: 'incidents' | 'notes'; revision: number; change: () => void
}) {
  const keys = incidentIds(alerts).join(',')
  const resources = useResource(useCallback(async (signal: AbortSignal) => {
    const ids = new Set(keys ? keys.split(',') : [])
    if (selected && selected !== 'new') ids.add(selected)
    const incidents = await Promise.all([...ids].map(id => api.incident(id, signal)))
    return incidents.sort((a, b) => b.updated_at.localeCompare(a.updated_at))
  }, [keys, selected, revision]))
  const incidents = resources.value ?? []
  const incident = selected === 'new' ? undefined : selected ? incidents.find(item => item.id === selected) : incidents[0]
  const unassigned = alerts.filter(alert => alert.incident_id === null)

  return <div className="investigation-layout">
    <section className="panel case-list">
      <div className="panel-heading"><div><h2>Investigations</h2><p>{resources.value ? incidents.length + ' linked incidents' : 'Linked to alerts'}</p></div></div>
      {mode === 'incidents' && <div className="case-action"><a className="button secondary" href="#incidents/new"><Plus size={17} />New incident</a></div>}
      {resources.loading && <State kind="loading" title="Loading investigations" />}
      {resources.error && <State kind="error" title="Could not load investigations" detail={resources.error} />}
      {resources.value && (incidents.length ? <ul className="case-items">{incidents.map(item => <li key={item.id}>
        <a href={'#' + mode + '/' + item.id} aria-current={incident?.id === item.id ? 'true' : undefined}>
          <FileSearch size={19} /><span><strong>{item.title}</strong><small>#{shortId(item.id)}</small><Status status={item.status} /></span>
        </a>
      </li>)}</ul> : <State title="No incidents yet" detail="Open an investigation from an unassigned alert." />)}
    </section>
    <section className="panel">
      <div className="panel-heading">
        <div><h2>{selected === 'new' ? 'New investigation' : incident?.title ?? (mode === 'notes' ? 'Investigation notes' : 'Incident details')}</h2>
          {incident && <p>#{shortId(incident.id)} · Updated {dateTime(incident.updated_at)}</p>}</div>
        {incident && <Status status={incident.status} />}
      </div>
      {selected === 'new' && mode === 'incidents' && <IncidentForm key={initialAlert} unassigned={unassigned} initialAlert={initialAlert} change={change} />}
      {selected !== 'new' && incident && (mode === 'notes'
        ? <NotePanel key={incident.id} incident={incident} change={change} />
        : <>
          <IncidentForm key={incident.id + incident.updated_at} incident={incident} unassigned={unassigned} change={change} />
          <div className="linked-alerts"><h3><ClipboardList size={18} /> Linked alerts</h3>
            <div>{incident.alert_ids.map(id => <a className="button secondary" key={id} href={'#alerts/' + id}>#{shortId(id)}</a>)}
              <a className="button secondary" href={'#notes/' + incident.id}>View notes</a></div>
          </div>
        </>)}
      {selected !== 'new' && resources.loading && <State kind="loading" title="Loading incident details" />}
      {selected !== 'new' && resources.value && !incident && <State title="Select an investigation" detail="Linked investigations appear here after you open a case." />}
    </section>
  </div>
}
