import { AlertCircle, Inbox, LoaderCircle } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import type { AlertStatus } from './api'

export function useResource<T>(load: ((signal: AbortSignal) => Promise<T>) | null, pollMs?: number, revision?: number) {
  const [result, setResult] = useState<{ source: typeof load; value?: T; error?: string } | null>(null)
  useEffect(() => {
    if (!load) return
    const request = load
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    async function run() {
      try {
        const value = await request(controller.signal)
        if (!controller.signal.aborted) setResult({ source: load, value })
      } catch (error) {
        if (!controller.signal.aborted) {
          setResult(previous => ({
            source: load, error: message(error),
            value: revision !== undefined && previous?.source === load ? previous.value : undefined,
          }))
        }
      } finally {
        if (pollMs && !controller.signal.aborted) timer = setTimeout(run, pollMs)
      }
    }
    void run()
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [load, pollMs, revision])
  const active = result?.source === load ? result : null
  return { value: active?.value, error: active?.error, loading: !!load && !active }
}

export function useDetailFocus(selected: string | undefined, close: RefObject<HTMLElement | null>,
  fallback: RefObject<HTMLElement | null>) {
  const opener = useRef<HTMLElement | null>(null)
  useEffect(() => {
    if (selected && close.current) {
      const current = document.activeElement
      if (!opener.current) {
        opener.current = current instanceof HTMLElement && current.closest('.table-scroll') ? current : fallback.current
      }
      close.current.focus()
    } else if (opener.current) {
      const target = opener.current.isConnected ? opener.current : fallback.current
      opener.current = null
      target?.focus()
    }
  }, [selected, close, fallback])
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
