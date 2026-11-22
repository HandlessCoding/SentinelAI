import { batchBody, type PreparedCsv } from './api'

const MAX_JSON_BYTES = 2 * 1024 * 1024
const encoder = new TextEncoder()
const envelopeBytes = encoder.encode(batchBody([])).length

export interface CsvBatch {
  start: number
  end: number
  key: string
  legacy?: { key: string; end: number }
}

export function planCsvBatches({
  records,
  batch_size: rowLimit,
  upload_id: upload,
}: PreparedCsv): CsvBatch[] {
  if (!Number.isInteger(rowLimit) || rowLimit < 1 || rowLimit > 100) {
    throw new Error('The API returned an invalid batch size.')
  }
  const batches: CsvBatch[] = []
  for (let offset = 0; offset < records.length; offset += rowLimit) {
    // Bound splits to the old row window so unaffected windows keep their keys.
    const end = Math.min(offset + rowLimit, records.length)
    const parts: Pick<CsvBatch, 'start' | 'end'>[] = []
    let start = offset
    let bytes = envelopeBytes
    for (let row = offset; row < end; row++) {
      const rowBytes = encoder.encode(JSON.stringify(records[row])).length
      if (envelopeBytes + rowBytes > MAX_JSON_BYTES) {
        throw new Error(`Record ${row + 1} exceeds the 2 MiB JSON request limit.`)
      }
      if (bytes + rowBytes + (row > start ? 1 : 0) > MAX_JSON_BYTES) {
        parts.push({ start, end: row })
        start = row
        bytes = envelopeBytes
      }
      bytes += rowBytes + (row > start ? 1 : 0)
    }
    parts.push({ start, end })
    const key = `csv-${upload}-${offset / rowLimit + 1}`
    batches.push(
      ...parts.map((part, index) => ({
        ...part,
        key: parts.length === 1 ? key : `${key}-part-${index + 1}`,
        legacy: parts.length > 1 && index === 0 ? { key, end } : undefined,
      })),
    )
  }
  return batches
}
