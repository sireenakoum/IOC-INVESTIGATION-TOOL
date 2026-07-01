import { VerdictPill } from '../utils/verdict'

function timeAgo(ts) {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts.replace(' ', 'T')).getTime()
  if (isNaN(diff)) return ts
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function HistoryTable({ rows, onViewHistory, onRescan }) {
  if (!rows?.length) {
    return <p style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif', padding: '16px 0' }}>No scans yet.</p>
  }

  return (
    <table className="w-full">
      <thead>
        <tr style={{ borderBottom: '1px solid #3c4a42' }}>
          {['Indicator', 'Verdict', 'Score', 'Time'].map(h => (
            <th key={h} className="text-left pb-2.5 pr-4 uppercase"
                style={{ fontSize: 10, color: '#86948a', fontWeight: 600, letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
              {h}
            </th>
          ))}
          <th />
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr
            key={i}
            style={{ borderBottom: '1px solid rgba(60,74,66,0.3)' }}
            className="group"
            onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <td className="py-2.5 pr-4"
                style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#e3e2e6' }}>
              {row.indicator}
            </td>
            <td className="py-2.5 pr-4">
              <VerdictPill verdict={row.verdict} />
            </td>
            <td className="py-2.5 pr-4 tabular-nums"
                style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'JetBrains Mono, monospace' }}>
              {row.score ?? '—'}
            </td>
            <td className="py-2.5 pr-4" style={{ fontSize: 11, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
              {timeAgo(row.timestamp)}
            </td>
            <td className="py-2.5 pl-2">
              <div
                className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center rounded overflow-hidden"
                style={{ border: '1px solid #3c4a42', display: 'inline-flex' }}
              >
                <button
                  onClick={() => onViewHistory(row.indicator)}
                  style={{
                    fontSize: 10,
                    color: '#4cd7f6',
                    background: 'transparent',
                    border: 'none',
                    borderRight: '1px solid #3c4a42',
                    padding: '3px 10px',
                    fontFamily: 'JetBrains Mono, monospace',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  VIEW
                </button>
                <button
                  onClick={() => onRescan(row.indicator)}
                  style={{
                    fontSize: 10,
                    color: '#4edea3',
                    background: 'transparent',
                    border: 'none',
                    padding: '3px 10px',
                    fontFamily: 'JetBrains Mono, monospace',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  RESCAN
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
