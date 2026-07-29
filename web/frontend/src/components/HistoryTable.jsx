import { useState, useEffect } from 'react'
import { VerdictPill } from '../utils/verdict'
import { timeAgo } from '../utils/time'
import ExportMenu from './ExportMenu'

const ACTION_BTN = {
  fontSize: 10,
  fontFamily: 'JetBrains Mono, monospace',
  padding: '3px 10px',
  background: 'transparent',
  border: 'none',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
  lineHeight: 1.4,
  display: 'inline-flex',
  alignItems: 'center',
}

export default function HistoryTable({ rows, onViewHistory, onRescan, onViewPivot, onExportReport, onExportEvidenceCsv, onExportJson, onExportDocx, onDeleteHistory }) {
  const [, refresh] = useState(0)
  useEffect(() => {
    const id = setInterval(() => refresh(n => n + 1), 10000)
    return () => clearInterval(id)
  }, [])

  if (!rows?.length) {
    return <p style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif', padding: '16px 0' }}>No scans yet.</p>
  }

  return (
    <div className="overflow-x-auto">
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
        {rows.map((row) => (
          <tr
            key={row.indicator}
            style={{ borderBottom: '1px solid rgba(60,74,66,0.3)' }}
            className="group"
            onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <td className="py-2.5 pr-4"
                style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#e3e2e6', maxWidth: 220 }}>
              <span className="block truncate">{row.indicator}</span>
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
                className="opacity-0 group-hover:opacity-100 transition-opacity flex items-stretch"
                style={{ display: 'inline-flex' }}
              >
                <button
                  onClick={() => onViewHistory(row.indicator)}
                  style={{ ...ACTION_BTN, color: '#4cd7f6', borderRight: '1px solid #3c4a42' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  VIEW
                </button>
                <button
                  onClick={() => onViewPivot(row.indicator)}
                  style={{ ...ACTION_BTN, color: '#f59e0b', borderRight: '1px solid #3c4a42' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  PIVOT
                </button>
                <button
                  onClick={() => onRescan(row.indicator)}
                  style={{ ...ACTION_BTN, color: '#4edea3', borderRight: '1px solid #3c4a42' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  RESCAN
                </button>
                <ExportMenu
                  indicator={row.indicator}
                  onExportReport={onExportReport}
                  onExportCsv={onExportEvidenceCsv}
                  onExportJson={onExportJson}
                  onExportDocx={onExportDocx}
                  variant="inline"
                />
                <button
                  onClick={() => onDeleteHistory(row.indicator)}
                  style={{ ...ACTION_BTN, color: '#b91c1c', borderLeft: '1px solid #3c4a42' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  DELETE
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  )
}