export type IncidentStatus = 'open' | 'investigating' | 'resolved'
export type AlertStatus = 'unreviewed' | IncidentStatus
export type NetworkRecord = Record<string, unknown>

export interface Alert {
  id: string
  batch_id: string
  record_index: number
  classification: 'suspected_attack'
  attack_probability: number
  model_version: string
  prediction_timestamp: string
  investigation_status: AlertStatus
  incident_id: string | null
}

export interface Note {
  id: string
  incident_id: string
  author: string
  text: string
  created_at: string
}

export interface Incident {
  id: string
  title: string
  description: string | null
  status: IncidentStatus
  created_at: string
  updated_at: string
  alert_ids: string[]
  notes: Note[]
}

export interface ModelInfo {
  model_version: string
  expected_feature_count: number
  decision_threshold: number
}

export interface PredictionBatch {
  model_version: string
  decision_threshold: number
  predictions: { label: 0 | 1; classification: 'normal' | 'attack'; attack_probability: number }[]
}

export interface Receipt {
  batch_id: string
  record_count: number
  model_version: string
  decision_threshold: number
  prediction_timestamp: string
  alert_ids: string[]
}

export interface PreparedCsv {
  columns: string[]
  records: Record<string, string>[]
  upload_id: string
  batch_size: number
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const response = await fetch('/api' + path, { ...options, headers })
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = body?.detail
    throw new Error(typeof detail === 'string' ? detail : `The API returned HTTP ${response.status}.`)
  }
  if (body === null) throw new Error('The API returned an unreadable response.')
  return body as T
}

export const api = {
  health: (signal?: AbortSignal) => request<{ status: 'ok' }>('/health', { signal }),
  model: (signal?: AbortSignal) => request<ModelInfo>('/model/info', { signal }),
  async alerts(signal?: AbortSignal) {
    const alerts = new Map<string, Alert>()
    const limit = 100
    for (let offset = 0; ; offset += limit) {
      const page = await request<Alert[]>(`/alerts?limit=${limit}&offset=${offset}`, { signal })
      for (const alert of page) alerts.set(alert.id, alert)
      if (page.length < limit) return [...alerts.values()]
    }
  },
  alert: (id: string, signal?: AbortSignal) => request<Alert>('/alerts/' + encodeURIComponent(id), { signal }),
  incident: (id: string, signal?: AbortSignal) => request<Incident>('/incidents/' + encodeURIComponent(id), { signal }),
  createIncident: (body: { title: string; description: string | null; alert_ids: string[] }) =>
    request<Incident>('/incidents', { method: 'POST', body: JSON.stringify(body) }),
  updateIncident: (id: string, body: { title: string; description: string | null; status: IncidentStatus }) =>
    request<Incident>('/incidents/' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify(body) }),
  addNote: (id: string, body: { author: string; text: string }) =>
    request<Note>('/incidents/' + encodeURIComponent(id) + '/notes', { method: 'POST', body: JSON.stringify(body) }),
  previewCsv: (file: File, signal?: AbortSignal) =>
    request<PreparedCsv>('/csv/preview', {
      method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: file, signal,
    }),
  predict: (records: NetworkRecord[], signal?: AbortSignal) =>
    request<PredictionBatch>('/predict', { method: 'POST', body: JSON.stringify({ records }), signal }),
  analyze: (records: NetworkRecord[], key: string, signal?: AbortSignal) =>
    request<Receipt>('/analyze', {
      method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify({ records }), signal,
    }),
}

export function incidentIds(alerts: Alert[]) {
  return [...new Set(alerts.flatMap(alert => alert.incident_id ? [alert.incident_id] : []))]
}

export function parseRecords(text: string): NetworkRecord[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error('Enter valid JSON or load the synthetic example.')
  }
  const records = parsed && typeof parsed === 'object' && 'records' in parsed ? parsed.records : parsed
  if (!Array.isArray(records) || records.length < 1 || records.length > 100 ||
      records.some(record => !record || typeof record !== 'object' || Array.isArray(record))) {
    throw new Error('Provide an array of 1 to 100 record objects.')
  }
  return records
}
