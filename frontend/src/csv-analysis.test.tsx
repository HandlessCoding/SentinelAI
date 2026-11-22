import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Analyze } from './Analyze'
import type { PredictionBatch, Receipt } from './api'
import synthetic from './synthetic-records.json'

const uploadId = 'a'.repeat(64)
const columns = Object.keys(synthetic[0])
const timestamp = '2026-11-21T12:00:00Z'
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
const csvFile = (records = synthetic) => new File([
  [columns.join(','), ...records.map(record => Object.values(record).join(','))].join('\n'),
], 'synthetic.csv', { type: 'text/csv' })

function prepared(records = synthetic) {
  return { columns, records, upload_id: uploadId, batch_size: 100 }
}

function csvMode() {
  render(<Analyze refresh={vi.fn()} />)
  fireEvent.click(screen.getByRole('tab', { name: 'CSV upload' }))
}

function choose(file: File) {
  fireEvent.change(screen.getByLabelText('CSV file'), { target: { files: [file] } })
}

function drop(file: File) {
  fireEvent.drop(screen.getByRole('region', { name: 'CSV upload drop zone' }), {
    dataTransfer: { files: [file], types: ['Files'] },
  })
}

function predictions(records: (typeof synthetic)[number][]): PredictionBatch {
  return {
    model_version: 'synthetic-model',
    decision_threshold: .5,
    predictions: records.map(record => record.proto === 'tcp'
      ? { label: 1, classification: 'attack', attack_probability: .86 }
      : { label: 0, classification: 'normal', attack_probability: .24 }),
  }
}

function receipt(id: string, count: number): Receipt {
  return {
    batch_id: 'batch-' + id,
    record_count: count,
    model_version: 'synthetic-model',
    decision_threshold: .5,
    prediction_timestamp: timestamp,
    alert_ids: ['alert-' + id],
  }
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('CSV analysis', () => {
  it('selects a CSV, uploads the raw file for validation, and shows a record preview before scoring', async () => {
    const fetcher = vi.fn(async (_path: string, _options: RequestInit) => json(prepared()))
    vi.stubGlobal('fetch', fetcher)
    csvMode()
    const file = csvFile()
    choose(file)

    expect(await screen.findByRole('heading', { name: 'Record preview' })).toBeTruthy()
    expect(screen.getByText('synthetic.csv')).toBeTruthy()
    expect(screen.getAllByText(synthetic[0].proto).length).toBeGreaterThan(0)
    expect(fetcher).toHaveBeenCalledTimes(1)
    const [[path, options]] = fetcher.mock.calls
    expect(path).toBe('/api/csv/preview')
    expect(options.method).toBe('POST')
    expect(options.body).toBe(file)
    expect(new Headers(options.headers).get('Content-Type')).toBe('text/csv')
  })

  it('supports drag-and-drop and leaves the manual JSON workflow accessible', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(prepared())))
    render(<Analyze refresh={vi.fn()} />)
    const draft = '{"records":[{"proto":"tcp"}]}'
    fireEvent.change(screen.getByLabelText('Network records JSON'), { target: { value: draft } })
    fireEvent.click(screen.getByRole('tab', { name: 'CSV upload' }))
    drop(csvFile())
    expect(await screen.findByRole('heading', { name: 'Record preview' })).toBeTruthy()

    fireEvent.click(screen.getByRole('tab', { name: 'Manual JSON' }))
    expect((screen.getByLabelText('Network records JSON') as HTMLTextAreaElement).value).toBe(draft)
    expect(screen.getByRole('button', { name: 'Preview predictions' })).toBeTruthy()
  })

  it('rejects wrong file types and oversized files before making an upload request', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    csvMode()

    choose(new File(['{}'], 'synthetic.json', { type: 'application/json' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/\.csv/i)
    drop(new File([new Uint8Array(2 * 1024 * 1024 + 1)], 'oversized.csv', { type: 'text/csv' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/2 MiB/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('displays a field-level error returned by CSV validation and sends no predictions', async () => {
    const fetcher = vi.fn(async () => json({ detail: 'CSV row 3: invalid dur value.' }, 422))
    vi.stubGlobal('fetch', fetcher)
    csvMode()
    choose(csvFile())

    expect((await screen.findByRole('alert')).textContent).toContain('CSV row 3: invalid dur value.')
    expect(screen.queryByRole('heading', { name: 'Record preview' })).toBeNull()
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('scores records in order in batches of at most 100 and allows inspection of a prediction', async () => {
    const records = Array.from({ length: 205 }, (_, index) => ({
      ...synthetic[index % synthetic.length], dur: String(index),
    }))
    const sends: string[][] = []
    let finishSecond: () => void = () => {}
    const second = new Promise<void>(resolve => { finishSecond = resolve })
    const fetcher = vi.fn(async (path: string, options: RequestInit) => {
      if (path === '/api/csv/preview') return json(prepared(records))
      expect(path).toBe('/api/predict')
      const batch = JSON.parse(String(options.body)).records as typeof records
      sends.push(batch.map(record => record.dur))
      if (sends.length === 2) await second
      return json(predictions(batch))
    })
    vi.stubGlobal('fetch', fetcher)
    csvMode()
    choose(csvFile(records))
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))

    await waitFor(() => expect(sends).toHaveLength(2))
    const progress = screen.getByRole('progressbar', { name: 'Scoring progress' }) as HTMLProgressElement
    expect(progress.value).toBe(100)
    finishSecond()
    await screen.findByText('205 of 205 records scored')
    expect(sends.map(batch => batch.length)).toEqual([100, 100, 5])
    expect(sends.flat()).toEqual(records.map(record => record.dur))
    expect(screen.getByText('Total records').nextElementSibling?.textContent).toBe('205')
    expect(screen.getByText('Suspected attacks').nextElementSibling?.textContent).toBe('137')
    expect(screen.getByText('Predicted normal').nextElementSibling?.textContent).toBe('68')

    fireEvent.click(screen.getByRole('button', { name: 'Inspect record 1' }))
    const detail = within(screen.getByRole('region', { name: 'Record 1 details' }))
    expect(detail.getByText(/Suspected attack.*86\.0% attack probability/)).toBeTruthy()
    expect(detail.getByText('proto').nextElementSibling?.textContent).toBe('tcp')
  })

  it('reuses each chunk key after a lost save response and after the same file is uploaded again', async () => {
    const records = Array.from({ length: 101 }, (_, index) => ({
      ...synthetic[index % synthetic.length], dur: String(index),
    }))
    const persisted = new Map<string, Receipt>()
    const keys: string[] = []
    let failOnce = true
    const fetcher = vi.fn(async (path: string, options: RequestInit) => {
      if (path === '/api/csv/preview') return json(prepared(records))
      const batch = JSON.parse(String(options.body)).records as typeof records
      if (path === '/api/predict') return json(predictions(batch))
      expect(path).toBe('/api/analyze')
      const key = new Headers(options.headers).get('Idempotency-Key')!
      keys.push(key)
      const previous = persisted.get(key)
      const saved = previous ?? receipt(String(persisted.size + 1), batch.length)
      persisted.set(key, saved)
      if (key.endsWith('-2') && failOnce) {
        failOnce = false
        throw new TypeError('Failed to fetch')
      }
      return json(saved, previous ? 200 : 201)
    })
    vi.stubGlobal('fetch', fetcher)
    csvMode()
    choose(csvFile(records))
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))
    const save = await screen.findByRole('button', { name: 'Save suspected alerts' })
    await waitFor(() => expect((save as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(save)

    expect((await screen.findByRole('alert')).textContent).toContain('Could not reach the local API.')
    const first = 'csv-' + uploadId + '-1'
    const second = 'csv-' + uploadId + '-2'
    expect(keys).toEqual([first, second])

    fireEvent.click(screen.getByRole('button', { name: 'Save suspected alerts' }))
    expect(await screen.findByRole('heading', { name: 'CSV analysis saved' })).toBeTruthy()
    expect(keys).toEqual([first, second, second])

    choose(csvFile(records))
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))
    const saveAgain = await screen.findByRole('button', { name: 'Save suspected alerts' })
    await waitFor(() => expect((saveAgain as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(saveAgain)
    expect(await screen.findByRole('heading', { name: 'CSV analysis saved' })).toBeTruthy()
    expect(keys).toEqual([first, second, second, first, second])
    expect([...persisted.keys()]).toEqual([first, second])
  })

  it('splits only oversized encoded windows and retries the exact committed batch', async () => {
    const largeService = '\\🙂'.repeat(30_000)
    const records = Array.from({ length: 101 }, (_, index) => ({
      ...synthetic[0], dur: String(index), ...(index >= 10 && index < 22 ? { service: largeService } : {}),
    }))
    const encoded = new TextEncoder()
    const scored: string[] = []
    const submitted: string[] = []
    const persisted = new Map<string, Receipt>()
    let loseFirstResponse = true
    const fetcher = vi.fn(async (path: string, options: RequestInit) => {
      if (path === '/api/csv/preview') return json(prepared(records))
      if (path === '/api/csv/receipts') return json({})
      const body = String(options.body)
      if (encoded.encode(body).length > 2 * 1024 * 1024) return json({ detail: 'Too large' }, 413)
      const batch = JSON.parse(body).records as typeof records
      if (path === '/api/predict') {
        scored.push(body)
        return json(predictions(batch))
      }
      const key = new Headers(options.headers).get('Idempotency-Key')!
      submitted.push(key)
      const saved = persisted.get(key) ?? receipt(String(persisted.size + 1), batch.length)
      persisted.set(key, saved)
      if (loseFirstResponse) {
        loseFirstResponse = false
        throw new TypeError('Failed to fetch')
      }
      expect(scored).toContain(body)
      return json(saved)
    })
    vi.stubGlobal('fetch', fetcher)
    csvMode()
    choose(csvFile())
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))
    await screen.findByText('101 of 101 records scored')
    const save = screen.getByRole('button', { name: 'Save suspected alerts' })
    fireEvent.click(save)
    await screen.findByText(/Saving stopped at record 1/)
    fireEvent.click(save)
    await screen.findByRole('heading', { name: 'CSV analysis saved' })
    const first = `csv-${uploadId}-1-part-1`
    expect(submitted).toEqual([first, first, `csv-${uploadId}-1-part-2`, `csv-${uploadId}-2`])
    expect([...persisted.values()].reduce((sum, item) => sum + item.record_count, 0)).toBe(101)
    expect(scored.flatMap(body => (JSON.parse(body).records as typeof records).map(row => row.dur)))
      .toEqual(records.map(row => row.dur))
  })

  it('uses the existing receipt for a legacy oversized window and only submits later windows', async () => {
    const records = Array.from({ length: 101 }, (_, index) => ({
      ...synthetic[0], ...(index < 12 ? { service: '\\🙂'.repeat(30_000) } : {}),
    }))
    const file = csvFile()
    const keys: (string | null)[] = []
    const fetcher = vi.fn(async (path: string, options: RequestInit) => {
      if (path === '/api/csv/preview') return json(prepared(records))
      if (path === '/api/csv/receipts') {
        expect(options.body).toBe(file)
        return json({ [`csv-${uploadId}-1`]: receipt('historic', 100) })
      }
      const { records: batch } = JSON.parse(String(options.body))
      if (path === '/api/predict') return json(predictions(batch))
      keys.push(new Headers(options.headers).get('Idempotency-Key'))
      return json(receipt('new', batch.length))
    })
    vi.stubGlobal('fetch', fetcher)
    csvMode()
    choose(file)
    fireEvent.click(await screen.findByRole('button', { name: 'Analyze CSV' }))
    await screen.findByText('101 of 101 records scored')
    fireEvent.click(screen.getByRole('button', { name: 'Save suspected alerts' }))
    await screen.findByRole('heading', { name: 'CSV analysis saved' })
    expect(keys).toEqual([`csv-${uploadId}-2`])
  })
})
