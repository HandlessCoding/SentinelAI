import { Braces, FileSpreadsheet, FileUp, FlaskConical, Play, ShieldAlert } from 'lucide-react'
import { useEffect, useRef, useState, type ChangeEvent, type KeyboardEvent } from 'react'
import { api, parseRecords, type ModelInfo, type PredictionBatch, type Receipt } from './api'
import { CsvAnalysis } from './CsvAnalysis'
import demo from './synthetic-records.json'
import { message, percentage, shortId, State } from './shared'

type AnalyzeProps = { model?: ModelInfo; refresh: () => void }
type InputMode = 'manual' | 'csv'
const MAX_MANUAL_JSON_BYTES = 2 * 1024 * 1024

export function Analyze({ model, refresh }: AnalyzeProps) {
  const [mode, setMode] = useState<InputMode>('manual')
  const manualTab = useRef<HTMLButtonElement>(null)
  const csvTab = useRef<HTMLButtonElement>(null)

  function moveTab(event: KeyboardEvent) {
    const key = event.key
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(key)) return
    event.preventDefault()
    const next = key === 'Home' ? 'manual' : key === 'End' ? 'csv' : mode === 'manual' ? 'csv' : 'manual'
    setMode(next)
    const tab = next === 'manual' ? manualTab : csvTab
    tab.current?.focus()
  }

  return <>
    <div className="analysis-mode-tabs" role="tablist" aria-label="Input format" onKeyDown={moveTab}>
      <button className="button secondary" id="manual-tab" ref={manualTab} role="tab"
        aria-selected={mode === 'manual'} aria-controls="manual-analysis" tabIndex={mode === 'manual' ? 0 : -1}
        onClick={() => setMode('manual')}><Braces size={17} />Manual JSON</button>
      <button className="button secondary" id="csv-tab" ref={csvTab} role="tab"
        aria-selected={mode === 'csv'} aria-controls="csv-analysis" tabIndex={mode === 'csv' ? 0 : -1}
        onClick={() => setMode('csv')}><FileSpreadsheet size={17} />CSV upload</button>
    </div>
    <div role="tabpanel" id="manual-analysis" aria-labelledby="manual-tab" hidden={mode !== 'manual'}>
      <ManualAnalysis model={model} refresh={refresh} />
    </div>
    <div role="tabpanel" id="csv-analysis" aria-labelledby="csv-tab" hidden={mode !== 'csv'}>
      <CsvAnalysis refresh={refresh} />
    </div>
  </>
}

function ManualAnalysis({ model, refresh }: AnalyzeProps) {
  const [text, setText] = useState('')
  const [synthetic, setSynthetic] = useState(false)
  const [busy, setBusy] = useState<'preview' | 'save' | 'import' | ''>('')
  const [error, setError] = useState('')
  const [predictions, setPredictions] = useState<PredictionBatch>()
  const [receipt, setReceipt] = useState<Receipt>()
  const retry = useRef<{ payload: string; key: string } | null>(null)
  const file = useRef<HTMLInputElement>(null)
  const operation = useRef<AbortController | null>(null)

  useEffect(() => () => operation.current?.abort(), [])

  function replace(value: string, example = false) {
    setText(value)
    setSynthetic(example)
    setPredictions(undefined)
    setReceipt(undefined)
    setError('')
  }

  async function perform(action: 'preview' | 'save' | 'import', work: (signal: AbortSignal) => Promise<void>) {
    if (operation.current) return
    const controller = new AbortController()
    operation.current = controller
    setBusy(action)
    setError('')
    try {
      await work(controller.signal)
    } catch (error) {
      if (!controller.signal.aborted) setError(message(error))
    } finally {
      operation.current = null
      if (!controller.signal.aborted) setBusy('')
    }
  }

  function importFile(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0]
    event.target.value = ''
    if (!selected) return
    return perform('import', async signal => {
      if (selected.size === 0 || selected.size > MAX_MANUAL_JSON_BYTES) {
        throw new Error('Choose a nonempty JSON file no larger than 2 MiB.')
      }
      const contents = await selected.text()
      if (!signal.aborted) replace(contents)
    })
  }

  function submit(action: 'preview' | 'save') {
    return perform(action, async signal => {
      if (text.length > MAX_MANUAL_JSON_BYTES || new TextEncoder().encode(text).byteLength > MAX_MANUAL_JSON_BYTES) {
        throw new Error('Manual JSON must be at most 2 MiB.')
      }
      const records = parseRecords(text)
      if (action === 'preview') {
        const result = await api.predict(records, signal)
        if (!signal.aborted) setPredictions(result)
      } else {
        const payload = JSON.stringify(records)
        if (retry.current?.payload !== payload) retry.current = { payload, key: crypto.randomUUID() }
        const result = await api.analyze(records, retry.current.key, signal)
        if (!signal.aborted) {
          setReceipt(result)
          refresh()
        }
      }
    })
  }

  return <div className="analysis-layout">
    <section className="panel">
      <div className="panel-heading"><div><h2>Network records</h2><p>Prepared UNSW-NB15 JSON · 1–100 records per batch</p></div><Braces size={23} className="muted" /></div>
      <div className="analysis-input">
        <div className="input-actions">
          <button className="button secondary" disabled={!!busy} onClick={() => replace(JSON.stringify({ records: demo }, null, 2), true)}><FlaskConical size={17} />Load synthetic example</button>
          <button className="button secondary" disabled={!!busy} onClick={() => file.current?.click()}><FileUp size={17} />Import JSON</button>
          <input type="file" ref={file} hidden aria-label="JSON file" accept=".json,application/json" disabled={!!busy} onChange={importFile} />
        </div>
        {synthetic && <p className="demo-label"><FlaskConical size={16} />Synthetic example loaded. These records are for demonstration.</p>}
        <textarea aria-label="Network records JSON" spellCheck={false} className="code-input" value={text}
          placeholder={'{\n  "records": [ … ]\n}'} disabled={!!busy} onChange={event => replace(event.target.value)} />
        {error && <p className="inline-error" role="alert">{error}</p>}
        <div className="input-actions">
          <button className="button primary" disabled={!!busy || !text.trim()} onClick={() => submit('preview')}><Play size={17} />{busy === 'preview' ? 'Scoring…' : 'Preview predictions'}</button>
          <button className="button secondary" disabled={!!busy || !text.trim()} onClick={() => submit('save')}><ShieldAlert size={17} />{busy === 'save' ? 'Saving…' : 'Analyze and save alerts'}</button>
        </div>
      </div>
    </section>
    <section className="panel">
      <div className="panel-heading"><div><h2>Results</h2><p>{model ? `${model.expected_feature_count} features · ${percentage(model.decision_threshold)} decision threshold` : 'Prediction and persistence results'}</p></div></div>
      {busy && <State kind="loading" title={busy === 'preview' ? 'Scoring records' : busy === 'save' ? 'Saving suspected alerts' : 'Reading JSON file'} />}
      {!busy && !predictions && !receipt && <State title="No results yet" detail="Preview to score without saving, or analyze to persist suspected alerts." />}
      {predictions && <div className="prediction-list">
        <h3>Prediction preview</h3>
        <p className="muted">Model {predictions.model_version}</p>
        <ul>{predictions.predictions.map((item, index) => <li key={index}>
          <span><strong>Record {index + 1}</strong><small>{item.label === 1 ? 'Suspected attack' : 'Normal'}</small></span>
          <strong>{percentage(item.attack_probability)}</strong>
        </li>)}</ul>
      </div>}
      {receipt && <div className="prediction-list">
        <h3>Batch saved</h3><p className="muted">#{shortId(receipt.batch_id)} · {receipt.alert_ids.length} suspected alerts from {receipt.record_count} records</p>
        <div className="input-actions">{receipt.alert_ids.map(id => <a key={id} className="button secondary" href={'#alerts/' + id}>Alert #{shortId(id)}</a>)}</div>
      </div>}
    </section>
  </div>
}
