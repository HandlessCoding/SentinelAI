import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import App from './App'
import type { TrafficDetail, TrafficFlow } from './api'
import { TRAFFIC_POLL_MS } from './Traffic'

const flow: TrafficFlow = {
  id: '12345678-1234-4234-8234-123456789abc', capture_id: 'test-capture', source_row: 1,
  source: 'authorized_lab', ingested_at: null,
  observed_at: '2026-01-01T00:00:01.123456789Z', proto: 'tcp', conn_state: 'REJ', service: null,
  orig_host: '192.0.2.1', orig_port: 31000, resp_host: '2001:db8::1', resp_port: 443, ground_truth: 'benign',
  finding: { source: 'rule', code: 'tcp-rejected-v1', explanation: 'Zeek recorded a rejected TCP connection attempt.' },
}
const detail: TrafficDetail = {
  ...flow, history: 'Sr', duration_ns: '50000', orig_pkts: '1', resp_pkts: '1', orig_ip_bytes: '80', resp_ip_bytes: '80',
  source_file: null, source_offset: null,
  orig_bytes: '0', resp_bytes: '0', missed_bytes: '0', label_category: null, label_reason: 'reviewed_window',
  capture: { session_id: 'test-session', environment_id: 'test-env', observation_point: 'test-point',
    source: 'authorized_lab', zeek_version: 'Zeek 8.0.11', imported_at: '2026-01-01T00:01:00Z',
    pcap_sha256: 'a'.repeat(64), conn_sha256: 'b'.repeat(64), manifest_sha256: 'c'.repeat(64) },
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const emptyMonitoring = { recent_flows: 0, recent_findings: 0, protocols: [], sources: [], more_sources: false }

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  window.location.hash = ''
})

it('shows real API counts, filters flow pages, and separates findings from reviewed labels', async () => {
  window.location.hash = '#traffic'
  const fetcher = vi.fn(async (path: string) => {
    if (path === '/api/health') return json({ status: 'ok' })
    if (path === '/api/model/info') return json({ model_version: 'fixture-model' })
    if (path === '/api/traffic/summary') return json({ total_flows: 1, finding_count: 1, protocols: [{ protocol: 'tcp', count: 1 }] })
    if (path === '/api/traffic/monitoring') return json(emptyMonitoring)
    if (path.startsWith('/api/traffic/flows?')) return json({ flows: [flow], next_offset: null })
    if (path === '/api/traffic/flows/' + flow.id) return json(detail)
    return json({ detail: 'Unexpected request' }, 404)
  })
  vi.stubGlobal('fetch', fetcher)
  render(<App />)
  expect(await screen.findByRole('heading', { name: 'Network traffic' })).toBeTruthy()
  expect(await screen.findByText('Protocol breakdown')).toBeTruthy()
  expect(await screen.findByText('[2001:db8::1]:443')).toBeTruthy()
  expect(screen.getByText('Reviewed benign')).toBeTruthy()
  fireEvent.change(screen.getByRole('combobox', { name: 'Filter by protocol' }), { target: { value: 'tcp' } })
  fireEvent.change(screen.getByRole('combobox', { name: 'Filter by rule finding' }), { target: { value: 'true' } })
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) =>
    path.includes('protocol=tcp') && path.includes('has_finding=true'))).toBe(true))
  const link = await screen.findByRole('link', { name: 'View flow 12345678' })
  link.focus()
  window.location.hash = link.getAttribute('href')!
  const panel = await screen.findByRole('complementary', { name: 'Flow details' })
  expect(await within(panel).findByText('tcp-rejected-v1')).toBeTruthy()
  expect(within(panel).getByText('Reviewed benign', { exact: false })).toBeTruthy()
  expect(within(panel).getByText('test-session')).toBeTruthy()
  expect(within(panel).getByText('Unavailable')).toBeTruthy()
  expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/alerts'))).toBe(false)
  expect(document.activeElement).toBe(within(panel).getByRole('link', { name: 'Close flow details' }))
  fireEvent.keyDown(panel, { key: 'Escape' })
  await waitFor(() => expect(document.activeElement).toBe(link))
})

it('offers a retry for the traffic query and guides the analyst through an empty import list', async () => {
  let ready = false
  window.location.hash = '#traffic'
  vi.stubGlobal('fetch', vi.fn(async (path: string) => {
    if (path === '/api/traffic/summary') return json({ total_flows: 0, finding_count: 0, protocols: [] })
    if (path === '/api/traffic/monitoring') return json(emptyMonitoring)
    if (path.startsWith('/api/traffic/flows?')) {
      return ready ? json({ flows: [], next_offset: null }) : json({ detail: 'Database unavailable.' }, 503)
    }
    return json({ status: 'ok' })
  }))
  render(<App />)
  expect(await screen.findByText('Could not load flows')).toBeTruthy()
  ready = true
  fireEvent.click(screen.getByRole('button', { name: 'Retry flows' }))
  expect(await screen.findByText('Import a reviewed Zeek capture to get started.')).toBeTruthy()
})

it('polls incoming records and presents replay health and filters', async () => {
  vi.useFakeTimers()
  window.location.hash = '#traffic'
  const recorded = { ...flow, source: 'recorded_replay', ingested_at: '2026-01-01T00:01:00Z' }
  let appended = false
  const fetcher = vi.fn(async (path: string) => {
    if (path === '/api/traffic/summary') return json({ total_flows: Number(appended), finding_count: 0, protocols: [] })
    if (path === '/api/traffic/monitoring') return json(appended ? {
      recent_flows: 1, recent_findings: 0, protocols: [{ protocol: 'tcp', count: 1 }], more_sources: false,
      sources: [{ capture_id: 'local-replay', source: 'recorded_replay', status: 'ready', backlog_bytes: 0,
        rejected_rows: 2, duplicate_rows: 1, last_error: 'rejected_record', replay_capture_id: 'recording',
        last_success_at: recorded.ingested_at, last_ingested_at: recorded.ingested_at }],
    } : emptyMonitoring)
    if (path.startsWith('/api/traffic/flows?')) return json({ flows: appended ? [recorded] : [], next_offset: null })
    return json({ status: 'ok' })
  })
  vi.stubGlobal('fetch', fetcher)
  await act(async () => { render(<App />) })
  expect(screen.getByText('No ingestion source registered')).toBeTruthy()
  appended = true
  await act(async () => { await vi.advanceTimersByTimeAsync(TRAFFIC_POLL_MS) })
  const health = screen.getByRole('region', { name: 'Ingestion source health' })
  expect(within(health).getByText('0 bytes pending')).toBeTruthy()
  expect(within(health).getByText(/2 rejected/)).toBeTruthy()
  expect(within(health).getByText('local-replay')).toBeTruthy()
  expect(within(health).getByRole('cell', { name: /Original capture ID recording/ })).toBeTruthy()
  expect(screen.getByText('Stored flows')).toBeTruthy()
  expect(within(screen.getByRole('region', { name: 'Flow table' })).getByText('Recorded replay')).toBeTruthy()
  fireEvent.change(screen.getByRole('combobox', { name: 'Filter by input kind' }), { target: { value: 'recorded_replay' } })
  fireEvent.change(screen.getByRole('combobox', { name: 'Sort connections' }), { target: { value: 'ingested' } })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Apply filters' })) })
  expect(fetcher.mock.calls.some(([path]) => path.includes('source=recorded_replay&order=ingested'))).toBe(true)
})

it('opens later pages with a cursor and returns to the same first page until browsing resumes live', async () => {
  window.location.hash = '#traffic'
  const fetcher = vi.fn(async (path: string) => {
    if (path === '/api/traffic/monitoring') return json(emptyMonitoring)
    if (path === '/api/traffic/summary') return json({ total_flows: 2, finding_count: 1, protocols: [] })
    if (path.startsWith('/api/traffic/flows?')) {
      const cursor = new URL(path, 'http://localhost').searchParams.get('cursor')
      if (cursor === 'second-page') return json({ flows: [{ ...flow, orig_host: '192.0.2.2' }],
        next_offset: null, page_cursor: 'second-page', next_cursor: null })
      return json({ flows: [flow], next_offset: null, page_cursor: 'first-page', next_cursor: 'second-page' })
    }
    return json({ status: 'ok' })
  })
  vi.stubGlobal('fetch', fetcher)
  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'Next' }))
  await screen.findByText('192.0.2.2:31000')
  fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
  await screen.findByText('192.0.2.1:31000')
  expect(fetcher.mock.calls.some(([path]) => path.includes('pagination=cursor') && path.includes('cursor=first-page'))).toBe(true)
  const count = fetcher.mock.calls.filter(([path]) => path.includes('pagination=cursor') && !path.includes('&cursor=')).length
  fireEvent.click(screen.getByRole('button', { name: 'Resume live' }))
  await waitFor(() => expect(fetcher.mock.calls.filter(([path]) =>
    path.includes('pagination=cursor') && !path.includes('&cursor=')).length).toBe(count + 1))
})
