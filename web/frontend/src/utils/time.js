// The backend stores timestamps as naive UTC strings (e.g. "2026-07-27T12:34:56"
// or "2026-07-27 12:34:56") with no timezone marker. `new Date(str)` on a string
// like that is parsed as *local* time by JS, not UTC — so every timestamp was off
// by the browser's UTC offset. Force UTC parsing here, then render in a fixed
// timezone so all users see the same wall-clock time regardless of where they are.
export function parseServerTimestamp(ts) {
  if (!ts) return null
  const iso = ts.replace(' ', 'T')
  const hasZone = /[Zz]|[+-]\d\d:?\d\d$/.test(iso)
  const d = new Date(hasZone ? iso : `${iso}Z`)
  return isNaN(d.getTime()) ? null : d
}

export function formatTimestamp(ts) {
  const d = parseServerTimestamp(ts)
  if (!d) return ts || '—'
  return d.toLocaleString('en-GB', {
    timeZone: 'Asia/Beirut',
    dateStyle: 'medium',
    timeStyle: 'medium',
  })
}

export function timeAgo(ts) {
  const d = parseServerTimestamp(ts)
  if (!d) return ts || '—'
  const diff = Date.now() - d.getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}
