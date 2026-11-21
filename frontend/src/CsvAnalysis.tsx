import { FileSpreadsheet, FileUp, Play, ShieldAlert, X } from 'lucide-react'
import { useEffect, useRef, useState, type DragEvent } from 'react'
import { api, type PredictionBatch, type PreparedCsv, type Receipt } from './api'
import { message, percentage, shortId, State } from './shared'

const MAX_FILE_BYTES = 2 * 1024 * 1024
const PREVIEW_ROWS = 5
const RESULT_ROWS = 10
const PREVIEW_FEATURES = ['proto', 'service', 'state', 'dur', 'rate']
type Prediction = PredictionBatch['predictions'][number]
type PredictionInfo = Pick<PredictionBatch, 'model_version' | 'decision_threshold'>
type Operation = 'upload' | 'score' | 'save'

export function CsvAnalysis({ refresh }: { refresh: () => void }) {
  const [prepared, setPrepared] = useState<PreparedCsv>()
  const [fileName, setFileName] = useState('')
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState<Operation | null>(null)
  const [error, setError] = useState('')
  const [predictions, setPredictions] = useState<Prediction[]>([])
  const [predictionInfo, setPredictionInfo] = useState<PredictionInfo>()
  const [receipts, setReceipts] = useState<Receipt[]>([])
  const [selected, setSelected] = useState<number | null>(null)
  const [page, setPage] = useState(0)
  const fileInput = useRef<HTMLInputElement>(null)
  const operation = useRef<AbortController | null>(null)
  const inspectHeading = useRef<HTMLHeadingElement>(null)
  const inspectOpener = useRef<HTMLButtonElement | null>(null)

  useEffect(() => () => operation.current?.abort(), [])
  useEffect(() => {
    if (selected !== null) inspectHeading.current?.focus()
  }, [selected])

  const total = prepared?.records.length ?? 0
  const attacks = predictions.filter(item => item.label === 1).length
  const savedRecords = receipts.reduce((count, receipt) => count + receipt.record_count, 0)
  const savedAlerts = receipts.reduce((count, receipt) => count + receipt.alert_ids.length, 0)
  const previewColumns = [
    ...PREVIEW_FEATURES.filter(name => prepared?.columns.includes(name)),
    ...(prepared?.columns.filter(name => !PREVIEW_FEATURES.includes(name)) ?? []),
  ].slice(0, 5)
  const selectedRecord = selected === null ? undefined : prepared?.records[selected]

  function inspect(index: number, button: HTMLButtonElement) {
    inspectOpener.current = button
    if (selected === index) inspectHeading.current?.focus()
    else setSelected(index)
  }

  function closeInspection() {
    setSelected(null)
    inspectOpener.current?.focus()
  }

  function begin(action: Operation) {
    if (operation.current) return null
    const controller = new AbortController()
    operation.current = controller
    setBusy(action)
    setError('')
    return controller
  }

  function finish(controller: AbortController) {
    if (operation.current !== controller) return
    operation.current = null
    if (!controller.signal.aborted) setBusy(null)
  }

  async function selectFiles(files: FileList | null) {
    if (!files?.length || operation.current) return
    setPrepared(undefined)
    setFileName('')
    setError('')
    setPredictions([])
    setPredictionInfo(undefined)
    setReceipts([])
    setSelected(null)
    setPage(0)
    if (files.length !== 1) {
      setError('Choose one CSV file at a time.')
      return
    }
    const file = files[0]
    if (!file.name.toLowerCase().endsWith('.csv')) {
      setError('Choose a file with a .csv extension.')
      return
    }
    if (file.size === 0 || file.size > MAX_FILE_BYTES) {
      setError('Choose a nonempty CSV file no larger than 2 MiB.')
      return
    }
    const controller = begin('upload')
    if (!controller) return
    try {
      const result = await api.previewCsv(file, controller.signal)
      if (!Number.isInteger(result.batch_size) || result.batch_size < 1 || result.batch_size > 100) {
        throw new Error('The API returned an invalid batch size.')
      }
      if (!controller.signal.aborted) {
        setPrepared(result)
        setFileName(file.name)
      }
    } catch (error) {
      if (!controller.signal.aborted) setError(message(error))
    } finally {
      finish(controller)
    }
  }

  function drop(event: DragEvent<HTMLElement>) {
    event.preventDefault()
    setDragging(false)
    void selectFiles(event.dataTransfer.files)
  }

  async function score() {
    if (!prepared || predictions.length >= total) return
    const controller = begin('score')
    if (!controller) return
    let cursor = predictions.length
    let info = predictionInfo
    try {
      while (cursor < total && !controller.signal.aborted) {
        const batch = prepared.records.slice(cursor, cursor + prepared.batch_size)
        const response = await api.predict(batch, controller.signal)
        if (controller.signal.aborted) return
        if (response.predictions.length !== batch.length) {
          throw new Error('The API returned a different number of predictions than records.')
        }
        const { model_version, decision_threshold } = response
        if (info && (info.model_version !== model_version || info.decision_threshold !== decision_threshold)) {
          throw new Error('The model changed during scoring. Upload the CSV again to start over.')
        }
        if (!info) {
          info = { model_version, decision_threshold }
          setPredictionInfo(info)
        }
        setPredictions(current => [...current, ...response.predictions])
        cursor += batch.length
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        setError(`Scoring stopped at record ${cursor + 1}. ${message(error)}`)
      }
    } finally {
      finish(controller)
    }
  }

  async function save() {
    if (!prepared || predictions.length !== total || attacks === 0 || savedRecords >= total) return
    const controller = begin('save')
    if (!controller) return
    let cursor = savedRecords
    try {
      while (cursor < total && !controller.signal.aborted) {
        const batch = prepared.records.slice(cursor, cursor + prepared.batch_size)
        const batchNumber = Math.floor(cursor / prepared.batch_size) + 1
        const receipt = await api.analyze(batch, `csv-${prepared.upload_id}-${batchNumber}`, controller.signal)
        if (controller.signal.aborted) return
        if (receipt.record_count !== batch.length) {
          throw new Error('The API returned a receipt for a different number of records.')
        }
        setReceipts(current => [...current, receipt])
        cursor += batch.length
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        setError(`Saving stopped at record ${cursor + 1}. Completed batches are retained. ${message(error)}`)
      }
    } finally {
      if (!controller.signal.aborted && cursor > savedRecords) refresh()
      finish(controller)
    }
  }

  return <div className="analysis-layout csv-layout">
    <section className="panel" aria-busy={busy === 'upload' || undefined}>
      <div className="panel-heading">
        <div><h2>Upload CSV</h2><p>UNSW-NB15 feature records · Up to 2 MiB and 1,000 records</p></div>
        <FileSpreadsheet size={23} className="muted" />
      </div>
      <div className="analysis-input">
        <section aria-label="CSV upload drop zone" className={'csv-dropzone' + (dragging ? ' is-dragging' : '')}
          onDragOver={event => { event.preventDefault(); if (!busy) setDragging(true) }}
          onDragLeave={event => {
            if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) {
              setDragging(false)
            }
          }} onDrop={drop}>
          <FileUp size={23} aria-hidden="true" />
          <strong>Drop a CSV file here</strong>
          <button className="button secondary" disabled={!!busy} onClick={() => fileInput.current?.click()}>
            Choose CSV file
          </button>
          <input ref={fileInput} type="file" hidden aria-label="CSV file" accept=".csv,text/csv" disabled={!!busy}
            onChange={event => { void selectFiles(event.currentTarget.files); event.currentTarget.value = '' }} />
        </section>
        {busy === 'upload' && <State kind="loading" title="Validating CSV" />}
        {error && <p className="inline-error" role="alert">{error}</p>}
        {prepared && <>
          <div className="csv-file-meta">
            <FileSpreadsheet size={18} aria-hidden="true" />
            <div><strong>{fileName}</strong><p className="muted">{total} records · {prepared.columns.length} predictor fields</p></div>
          </div>
          <div className="csv-preview">
            <h3>Record preview</h3>
            <p className="muted">Showing {Math.min(total, PREVIEW_ROWS)} of {total} records</p>
            <div className="table-scroll" role="region" aria-label="Scrollable record preview" tabIndex={0}><table aria-label="CSV record preview">
              <thead><tr><th>Record</th>{previewColumns.map(name => <th key={name}>{name}</th>)}<th aria-label="View fields" /></tr></thead>
              <tbody>{prepared.records.slice(0, PREVIEW_ROWS).map((record, index) => <tr key={index}>
                <td>{index + 1}</td>
                {previewColumns.map(name => <td key={name}>{record[name]}</td>)}
                <td><button className="button secondary" aria-label={`View fields for record ${index + 1}`}
                  onClick={event => inspect(index, event.currentTarget)}>View fields</button></td>
              </tr>)}</tbody>
            </table></div>
          </div>
          <div className="input-actions">
            <button className="button primary" disabled={!!busy || predictions.length === total} onClick={() => void score()}>
              <Play size={17} />{busy === 'score' ? 'Analyzing…' : 'Analyze CSV'}
            </button>
            <button className="button secondary" disabled={!!busy || predictions.length !== total || !attacks || savedRecords >= total}
              onClick={() => void save()}><ShieldAlert size={17} />{busy === 'save' ? 'Saving…' : 'Save suspected alerts'}</button>
          </div>
        </>}
      </div>
    </section>

    <section className="panel">
      <div className="panel-heading"><div><h2>CSV results</h2>
        <p>{predictionInfo
          ? `${predictionInfo.model_version} · ${percentage(predictionInfo.decision_threshold)} threshold`
          : 'Review predictions before saving suspected alerts.'}</p></div></div>
      {!predictions.length && busy !== 'score' && !selectedRecord && <State title="No CSV results yet" detail="Upload and analyze a CSV to see its predictions." />}
      {prepared && (busy === 'score' || predictions.length > 0) && <div className="prediction-list csv-progress">
        <p className="muted" role="status">{predictions.length} of {total} records scored</p>
        <progress aria-label="Scoring progress" max={total} value={predictions.length} />
      </div>}
      {!!predictions.length && <>
        <dl className="csv-summary">
          <div><dt>Total records</dt><dd>{total}</dd></div>
          <div><dt>Suspected attacks</dt><dd>{attacks}</dd></div>
          <div><dt>Predicted normal</dt><dd>{predictions.length - attacks}</dd></div>
        </dl>
        <div className="table-scroll" role="region" aria-label="Scrollable prediction results" tabIndex={0}><table aria-label="CSV predictions">
          <thead><tr><th>Record</th><th>Prediction</th><th>Attack probability</th><th aria-label="Inspect" /></tr></thead>
          <tbody>{predictions.slice(page * RESULT_ROWS, (page + 1) * RESULT_ROWS).map((prediction, index) => {
            const row = page * RESULT_ROWS + index
            return <tr key={row}>
              <td>{row + 1}</td><td>{prediction.label === 1 ? 'Suspected attack' : 'Normal'}</td>
              <td>{percentage(prediction.attack_probability)}</td>
              <td><button className="button secondary" aria-label={`Inspect record ${row + 1}`}
                onClick={event => inspect(row, event.currentTarget)}>Inspect</button></td>
            </tr>
          })}</tbody>
        </table></div>
        {predictions.length > RESULT_ROWS && <div className="input-actions csv-results-controls">
          <button className="button secondary" disabled={page === 0} onClick={() => setPage(value => value - 1)}>Previous results</button>
          <span className="muted">Page {page + 1} of {Math.ceil(predictions.length / RESULT_ROWS)}</span>
          <button className="button secondary" disabled={(page + 1) * RESULT_ROWS >= predictions.length} onClick={() => setPage(value => value + 1)}>Next results</button>
        </div>}
      </>}
      {selected !== null && selectedRecord && <section className="prediction-list csv-inspection" aria-labelledby="csv-record-details-title"
        onKeyDown={event => { if (event.key === 'Escape') { event.preventDefault(); closeInspection() } }}>
        <div className="input-actions">
          <h3 id="csv-record-details-title" ref={inspectHeading} tabIndex={-1}>Record {selected + 1} details</h3>
          <button className="icon-button" onClick={closeInspection} aria-label="Close record details"><X size={16} /></button>
        </div>
        {predictions[selected] && <p className="muted">
          {predictions[selected].label === 1 ? 'Suspected attack' : 'Normal'} · {percentage(predictions[selected].attack_probability)} attack probability
        </p>}
        <dl className="csv-facts">{prepared?.columns.map(name => <div key={name}><dt>{name}</dt><dd>{selectedRecord[name]}</dd></div>)}</dl>
      </section>}
      {prepared && (busy === 'save' || receipts.length > 0) && <div className="prediction-list csv-progress csv-receipts">
        <h3>{savedRecords === total ? 'CSV analysis saved' : 'Alert persistence'}</h3>
        <p className="muted" role="status">{savedRecords} of {total} records submitted · {savedAlerts} saved alerts</p>
        <progress aria-label="Saving progress" max={total} value={savedRecords} />
        {receipts.map((receipt, index) => <details key={receipt.batch_id} open={receipt.alert_ids.length > 0 && receipt.alert_ids.length <= 5}>
          <summary>Batch {index + 1} · {receipt.alert_ids.length} alerts</summary>
          {receipt.alert_ids.length > 0 && <div className="input-actions">
            {receipt.alert_ids.map(id => <a className="button secondary" key={id} href={'#alerts/' + id}>Alert #{shortId(id)}</a>)}
          </div>}
        </details>)}
      </div>}
    </section>
  </div>
}
