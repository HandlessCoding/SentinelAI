import { AlertCircle, Inbox, LoaderCircle } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import type { AlertStatus } from './api'

export function useResource<T>(load: ((signal: AbortSignal) => Promise<T>) | null) {
  const [result, setResult] = useState<{ source: typeof load; value?: T; error?: string } | null>(null)
  useEffect(() => {
    if (!load) return
    const controller = new AbortController()
    load(controller.signal).then(value => {
      if (!controller.signal.aborted) setResult({ source: load, value })
    }).catch((error: unknown) => {
      if (!controller.signal.aborted) setResult({ source: load, error: message(error) })
    })
    return () => controller.abort()
  }, [load])
  const active = result?.source === load ? result : null
  return { value: active?.value, error: active?.error, loading: !!load && !active }
}

export const statuses: Record<AlertStatus, string> = {
  unreviewed: 'Unreviewed', open: 'Open', investigating: 'Investigating', resolved: 'Resolved',
}
export const percentage = (value: number) => (value * 100).toFixed(1) + '%'
export const shortId = (id: string) => id.slice(0, 8).toUpperCase()
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
export const dateTime = (date: string) => dateFormat.format(new Date(date))
export const message = (error: unknown) => error instanceof Error
  ? /failed to fetch|networkerror/i.test(error.message) ? 'Could not reach the local API.' : error.message
  : 'Something went wrong.'

export function Status({ status }: { status: AlertStatus }) {
  return <span className={'status status-' + status}><span />{statuses[status]}</span>
}

export function State({ title, detail, kind = 'empty', children }: {
  title: string; detail?: string; kind?: 'empty' | 'loading' | 'error'; children?: ReactNode
}) {
  const Icon = kind === 'loading' ? LoaderCircle : kind === 'error' ? AlertCircle : Inbox
  return <div className={'state state-' + kind} role={kind === 'error' ? 'alert' : 'status'}>
    <Icon size={24} className={kind === 'loading' ? 'spin' : ''} aria-hidden="true" />
    <strong>{title}</strong>
    {detail && <p>{detail}</p>}
    {children}
  </div>
}
