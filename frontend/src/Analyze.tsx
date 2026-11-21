import { Braces, FileUp, FlaskConical, Play, ShieldAlert } from 'lucide-react'
import { useRef, useState, type ChangeEvent } from 'react'
import { api, parseRecords, type ModelInfo, type PredictionBatch, type Receipt } from './api'
import demo from './synthetic-records.json'
import { message, percentage, shortId, State } from './shared'

export function Analyze({ model, refresh }: { model?: ModelInfo; refresh: () => void }) {
  const [text, setText] = useState('')
  const [synthetic, setSynthetic] = useState(false)
  const [busy, setBusy] = useState<'preview' | 'save' | ''>('')
  const [error, setError] = useState('')
  const [predictions, setPredictions] = useState<PredictionBatch>()
  const [receipt, setReceipt] = useState<Receipt>()
  const retry = useRef<{ payload: string; key: string } | null>(null)
  const file = useRef<HTMLInputElement>(null)

  function replace(value: string, example = false) {
    setText(value)
    setSynthetic(example)
    setPredictions(undefined)
    setReceipt(undefined)
    setError('')
  }

  async function importFile(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0]
    event.target.value = ''
    if (!selected) return
    try {
      replace(await selected.text())
    } catch (error) {
      setError(message(error))
    }
  }

  async function submit(action: 'preview' | 'save') {
    setError('')
    setBusy(action)
    try {
      const records = parseRecords(text)
      if (action === 'preview') {
        setPredictions(await api.predict(records))
      } else {
        const payload = JSON.stringify(records)
        if (retry.current?.payload !== payload) retry.current = { payload, key: crypto.randomUUID() }
        setReceipt(await api.analyze(records, retry.current.key))
        refresh()
      }
    } catch (error) {
      setError(message(error))
    } finally {
      setBusy('')
    }
  }

  return <div className="analysis-layout">
    <section className="panel">
      <div className="panel-heading"><div><h2>Network records</h2><p>Prepared UNSW-NB15 JSON · 1–100 records per batch</p></div><Braces size={23} className="muted" /></div>
      <div className="analysis-input">
        <div className="input-actions">
          <button className="button secondary" disabled={!!busy} onClick={() => replace(JSON.stringify({ records: demo }, null, 2), true)}><FlaskConical size={17} />Load synthetic example</button>
          <button className="button secondary" disabled={!!busy} onClick={() => file.current?.click()}><FileUp size={17} />Import JSON</button>
          <input type="file" ref={file} hidden accept=".json,application/json" onChange={importFile} />
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
      {busy && <State kind="loading" title={busy === 'preview' ? 'Scoring records' : 'Saving suspected alerts'} />}
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
