import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { Analyze } from './Analyze'
import { Alerts, Overview } from './Alerts'
import { Investigations } from './Investigations'
import { api, parseRecords, type Alert, type Incident } from './api'

const first: Alert = {
  id: 'a0000001-0000-0000-0000-000000000000', batch_id: 'batch-found', record_index: 0,
  classification: 'suspected_attack', attack_probability: .91, model_version: 'model-1',
  prediction_timestamp: '2026-11-21T12:00:00Z', investigation_status: 'unreviewed', incident_id: null,
}
const second: Alert = {
  ...first, id: 'a0000002-0000-0000-0000-000000000000', batch_id: 'other-batch',
  attack_probability: .75, investigation_status: 'open', incident_id: 'incident-1',
}
const incident: Incident = {
  id: 'incident-1', title: 'Test incident', description: 'Context', status: 'open',
  created_at: '2026-11-21T12:00:00Z', updated_at: '2026-11-21T12:00:00Z',
  alert_ids: [second.id], notes: [],
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })

beforeEach(() => { window.location.hash = '#overview' })
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('dashboard', () => {
  it('computes real alert totals and deduplicates linked investigations', () => {
    render(<Overview alerts={[first, second, { ...second, id: 'third' }]} />)
    expect(within(screen.getByText('Total alerts').closest('article')!).getByText('3')).toBeTruthy()
    expect(within(screen.getByText('Active incidents').closest('article')!).getByText('1')).toBeTruthy()
    expect(screen.getByRole('img', { name: '2 linked alerts and 1 unreviewed alerts' })).toBeTruthy()
  })

  it('shows an explicit empty state for an empty store', () => {
    render(<Overview alerts={[]} />)
    expect(screen.getByText('No alerts to show')).toBeTruthy()
  })

  it('filters alerts by status and searches the batch ID', () => {
    render(<Alerts alerts={[first, second]} revision={0} />)
    expect(screen.getByText('2 of 2 alerts')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Search alerts'), { target: { value: 'batch-found' } })
    expect(screen.getByText('#A0000001')).toBeTruthy()
    expect(screen.queryByText('#A0000002')).toBeNull()
    fireEvent.change(screen.getByLabelText('Filter by status'), { target: { value: 'open' } })
    expect(screen.getByText('0 of 2 alerts')).toBeTruthy()
  })

  it('shows an API failure and recovers on retry', async () => {
    let online = false
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (!online) throw new TypeError('Failed to fetch')
      if (path.includes('/alerts?')) return json([])
      return json({ status: 'ok', model_version: 'model-1' })
    }))
    render(<App />)
    expect(await screen.findByText('API offline')).toBeTruthy()
    expect(await screen.findByText('Could not load alerts')).toBeTruthy()
    online = true
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('API connected')).toBeTruthy()
    expect(await screen.findByText('No alerts to show')).toBeTruthy()
  })

  it('previews on /predict and reuses the same analysis key for unchanged records', async () => {
    const fetcher = vi.fn(async (path: string, options: RequestInit) => {
      const records = JSON.parse(String(options.body)).records
      expect(records).toHaveLength(3)
      expect(Object.keys(records[0])).toHaveLength(42)
      if (path === '/api/predict') {
        return json({ model_version: 'model-1', decision_threshold: .5,
          predictions: [{ label: 1, classification: 'attack', attack_probability: .91 }] })
      }
      return json({ batch_id: first.batch_id, record_count: 3, alert_ids: [first.id] })
    })
    vi.stubGlobal('fetch', fetcher)
    render(<Analyze refresh={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Load synthetic example' }))
    expect(screen.getByText(/Synthetic example loaded/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Preview predictions' }))
    expect(await screen.findByText('91.0%')).toBeTruthy()
    expect(fetcher.mock.calls.map(([path]) => path)).toEqual(['/api/predict'])
    fireEvent.click(screen.getByRole('button', { name: 'Analyze and save alerts' }))
    expect(await screen.findByText('Batch saved')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Analyze and save alerts' }))
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(3))
    const analysisCalls = fetcher.mock.calls.filter(([path]) => path === '/api/analyze')
    const keys = analysisCalls.map(([, options]) => new Headers(options.headers).get('Idempotency-Key'))
    expect(keys[0]).toBeTruthy()
    expect(keys[0]).toBe(keys[1])
  })

  it('opens a case from an alert and posts notes to the chosen incident', async () => {
    const fetcher = vi.fn(async (path: string, options: RequestInit) =>
      json(path.endsWith('/notes') ? { id: 'note-1' } : { ...incident, alert_ids: [first.id] }, options.method === 'POST' ? 201 : 200))
    vi.stubGlobal('fetch', fetcher)
    const refresh = vi.fn()
    const createView = render(<Investigations alerts={[first]} selected="new" initialAlert={first.id} mode="incidents" revision={0} change={refresh} />)
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Case from alert' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create incident' }))
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1))
    const [createPath, createOptions] = fetcher.mock.calls[0]
    expect(createPath).toBe('/api/incidents')
    expect(JSON.parse(String(createOptions.body))).toEqual({ title: 'Case from alert', description: null, alert_ids: [first.id] })

    createView.unmount()
    render(<Investigations alerts={[second]} selected={incident.id} mode="notes" revision={0} change={refresh} />)
    fireEvent.change(await screen.findByLabelText('Analyst name'), { target: { value: 'Example analyst' } })
    fireEvent.change(screen.getByLabelText('Investigation note'), { target: { value: 'Reviewed evidence.' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add note' }))
    await waitFor(() => expect(refresh).toHaveBeenCalledTimes(2))
    const [notePath, noteOptions] = fetcher.mock.calls.at(-1)!
    expect(notePath).toBe('/api/incidents/incident-1/notes')
    expect(JSON.parse(String(noteOptions.body))).toEqual({ author: 'Example analyst', text: 'Reviewed evidence.' })
  })
})

describe('request helpers', () => {
  it('follows alert page offsets and returns all rows', async () => {
    const page = Array.from({ length: 100 }, (_, i) => ({ ...first, id: String(i) }))
    const fetcher = vi.fn(async (path: string) => json(path.endsWith('offset=0') ? page : [second]))
    vi.stubGlobal('fetch', fetcher)
    expect(await api.alerts()).toHaveLength(101)
    expect(fetcher.mock.calls.map(([path]) => path)).toEqual([
      '/api/alerts?limit=100&offset=0', '/api/alerts?limit=100&offset=100',
    ])
  })

  it('rejects malformed or oversized JSON before making a request', () => {
    expect(() => parseRecords('{')).toThrow('valid JSON')
    expect(() => parseRecords('{"records":[null]}')).toThrow('record objects')
    expect(() => parseRecords(JSON.stringify(Array.from({ length: 101 }, () => ({}))))).toThrow('1 to 100')
    expect(parseRecords('{"records":[{"service":"-"}]}')).toEqual([{ service: '-' }])
  })
})
