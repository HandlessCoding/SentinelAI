import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { Analyze } from './Analyze'
import { api, type Alert } from './api'
import synthetic from './synthetic-records.json'

const alert: Alert = {
  id: 'a0000001-0000-0000-0000-000000000000',
  batch_id: 'test-batch',
  record_index: 0,
  classification: 'suspected_attack',
  attack_probability: .91,
  model_version: 'test-model',
  prediction_timestamp: '2026-11-21T12:00:00Z',
  investigation_status: 'unreviewed',
  incident_id: null,
}
const model = { model_version: 'test-model', expected_feature_count: 42, decision_threshold: .5 }
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
const predictions = () => json({
  ...model,
  predictions: synthetic.map(() => ({ label: 1, classification: 'attack', attack_probability: .91 })),
})
const csv = () => new File(['synthetic CSV'], 'synthetic.csv', { type: 'text/csv' })
const prepared = () => json({
  columns: Object.keys(synthetic[0]), records: synthetic, upload_id: 'a'.repeat(64), batch_size: 100,
})

function navigate(hash: string) {
  window.history.replaceState(null, '', '#' + hash)
  window.dispatchEvent(new HashChangeEvent('hashchange'))
}

function stubWorkspace(status = 200) {
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    if (path === '/api/health') return json({ status: 'ok' })
    if (path === '/api/model/info') return json(model)
    if (path === '/api/predict') return predictions()
    if (path.startsWith('/api/alerts?')) {
      return status === 200 ? json([alert]) : json({ detail: 'Database unavailable.' }, status)
    }
    if (path === '/api/alerts/' + alert.id) return json(alert)
    throw new Error('Unexpected request: ' + path)
  }))
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('alert pagination', () => {
  const fullPage = Array.from({ length: 100 }, (_, index) => ({ ...alert, id: String(index) }))

  it('stops loading identical full pages', async () => {
    const fetchPage = vi.fn(async () => json(fullPage))
    vi.stubGlobal('fetch', fetchPage)
    await expect(api.alerts()).rejects.toThrow('Alert pages stopped advancing')
    expect(fetchPage).toHaveBeenCalledTimes(2)
  })

  it('keeps loading when the next page overlaps and contains new alerts', async () => {
    const secondPage = Array.from({ length: 100 }, (_, index) => ({ ...alert, id: String(99 + index) }))
    const fetchPage = vi.fn()
      .mockResolvedValueOnce(json(fullPage))
      .mockResolvedValueOnce(json(secondPage))
      .mockResolvedValueOnce(json([{ ...alert, id: '199' }]))
    vi.stubGlobal('fetch', fetchPage)
    expect(await api.alerts()).toHaveLength(200)
    expect(fetchPage).toHaveBeenCalledTimes(3)
  })
})

describe('keyboard navigation', () => {
  it('skips to main content without changing the current page', async () => {
    navigate('analyze')
    stubWorkspace()
    render(<App />)
    await screen.findByText('API connected')
    fireEvent.click(screen.getByRole('link', { name: 'Skip to main content' }))
    expect(document.activeElement).toBe(screen.getByRole('main'))
    expect(location.hash).toBe('#analyze')
  })

  it('keeps focus in the mobile menu and restores it after Escape', async () => {
    navigate('overview')
    stubWorkspace()
    render(<App />)
    await screen.findByText('API connected')
    const trigger = screen.getByRole('button', { name: 'Open navigation' })
    fireEvent.click(trigger)
    const menu = screen.getByRole('dialog', { name: 'Workspace navigation' })
    expect(menu.getAttribute('aria-modal')).toBe('true')
    expect(document.activeElement).toBe(within(menu).getByRole('link', { name: 'Overview' }))
    expect(screen.getByRole('main').closest('[inert]')).toBeTruthy()
    const last = within(menu).getByRole('link', { name: 'Analyze' })
    last.focus()
    expect(document.activeElement).toBe(last)
    fireEvent.keyDown(last, { key: 'Tab' })
    expect(document.activeElement).toBe(within(menu).getAllByRole('link')[0])
    fireEvent.keyDown(document.activeElement!, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(trigger)
  })

  it('moves focus into alert details and returns it to the opening link', async () => {
    navigate('alerts')
    stubWorkspace()
    render(<App />)
    const opener = await screen.findByRole('link', { name: 'View alert A0000001' })
    opener.focus()
    navigate('alerts/' + alert.id)
    const close = await screen.findByRole('link', { name: 'Close alert details' })
    expect(document.activeElement).toBe(close)
    expect(await screen.findByText('Batch ID')).toBeTruthy()
    fireEvent.keyDown(close, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Close alert details' })).toBeNull())
    expect(document.activeElement).toBe(opener)
  })

  it('switches modes by keyboard and announces and focuses CSV details', async () => {
    vi.stubGlobal('fetch', vi.fn(async (path: string) => path === '/api/csv/preview' ? prepared() : predictions()))
    render(<Analyze refresh={vi.fn()} />)
    const manual = screen.getByRole('tab', { name: 'Manual JSON' })
    manual.focus()
    fireEvent.keyDown(manual, { key: 'ArrowRight' })
    const csvTab = screen.getByRole('tab', { name: 'CSV upload' })
    expect(document.activeElement).toBe(csvTab)
    expect(csvTab.getAttribute('aria-selected')).toBe('true')
    fireEvent.change(screen.getByLabelText('CSV file'), { target: { files: [csv()] } })
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))
    expect((await screen.findByText('3 of 3 records scored')).getAttribute('role')).toBe('status')
    const inspect = screen.getByRole('button', { name: 'Inspect record 2' })
    fireEvent.click(inspect)
    const heading = screen.getByRole('heading', { name: 'Record 2 details' })
    expect(document.activeElement).toBe(heading)
    fireEvent.keyDown(heading, { key: 'Escape' })
    expect(screen.queryByRole('heading', { name: 'Record 2 details' })).toBeNull()
    expect(document.activeElement).toBe(inspect)
  })
})

describe('recoverable failures', () => {
  it('reports a database-only failure while keeping model predictions accessible', async () => {
    navigate('overview')
    stubWorkspace(503)
    render(<App />)
    expect(await screen.findByText('API connected')).toBeTruthy()
    expect((await screen.findByRole('alert')).textContent).toContain('Database unavailable.')
    expect(screen.queryByText('Total alerts')).toBeNull()
    fireEvent.click(screen.getByRole('link', { name: 'Analyze records' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Load synthetic example' }))
    fireEvent.click(screen.getByRole('button', { name: 'Preview predictions' }))
    expect(await screen.findByRole('heading', { name: 'Prediction preview' })).toBeTruthy()
  })

  it('keeps CSV scores and the idempotency key after a database save failure', async () => {
    const keys: (string | null)[] = []
    vi.stubGlobal('fetch', vi.fn(async (path: string, options: RequestInit) => {
      if (path === '/api/csv/preview') return prepared()
      if (path === '/api/predict') return predictions()
      keys.push(new Headers(options.headers).get('Idempotency-Key'))
      return keys.length === 1 ? json({ detail: 'Database unavailable.' }, 503) : json({
        batch_id: 'test-batch', record_count: 3, alert_ids: [alert.id],
      }, 201)
    }))
    render(<Analyze refresh={vi.fn()} />)
    fireEvent.click(screen.getByRole('tab', { name: 'CSV upload' }))
    fireEvent.change(screen.getByLabelText('CSV file'), { target: { files: [csv()] } })
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))
    await screen.findByText('3 of 3 records scored')
    fireEvent.click(screen.getByRole('button', { name: 'Save suspected alerts' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Database unavailable.')
    expect(screen.getByRole('table', { name: 'CSV predictions' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Save suspected alerts' }))
    expect(await screen.findByRole('heading', { name: 'CSV analysis saved' })).toBeTruthy()
    expect(keys).toEqual(['csv-' + 'a'.repeat(64) + '-1', 'csv-' + 'a'.repeat(64) + '-1'])
  })

  it('preserves the manual draft when the API rejects the payload size', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ detail: 'JSON request bodies must be at most 2 MiB.' }, 413)))
    render(<Analyze refresh={vi.fn()} />)
    const input = screen.getByLabelText('Network records JSON') as HTMLTextAreaElement
    const draft = '{"records":[{"proto":"tcp"}]}'
    fireEvent.change(input, { target: { value: draft } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview predictions' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/at most 2 MiB/)
    expect(input.value).toBe(draft)
    expect((screen.getByRole('button', { name: 'Preview predictions' }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('rejects oversized manual files before reading them and malformed inputs before posting', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    render(<Analyze refresh={vi.fn()} />)
    const file = new File([new Uint8Array(2 * 1024 * 1024 + 1)], 'large.json', { type: 'application/json' })
    const read = vi.fn()
    Object.defineProperty(file, 'text', { value: read })
    fireEvent.change(screen.getByLabelText('JSON file'), { target: { files: [file] } })
    expect((await screen.findByRole('alert')).textContent).toMatch(/no larger than 2 MiB/)
    expect(read).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText('Network records JSON'), { target: { value: '{' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview predictions' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/valid JSON/)
    expect(fetcher).not.toHaveBeenCalled()
  })
})
