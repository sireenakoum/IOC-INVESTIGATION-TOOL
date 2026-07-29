import { useState, useEffect } from 'react'
import { VerdictPill } from '../utils/verdict'
import { guessIndicatorType } from '../utils/indicatorType'
import { timeAgo, parseServerTimestamp } from '../utils/time'
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

function StatCard({ icon, label, value, subtitle, color }) {
  return (
    <div className="rounded p-4" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
      <div className="flex items-start justify-between mb-3">
        <div className="w-9 h-9 rounded flex items-center justify-center"
             style={{ background: `${color}1a`, border: `1px solid ${color}33` }}>
          <span className="material-symbols-outlined" style={{ fontSize: 18, color }}>{icon}</span>
        </div>
      </div>
      <p className="font-bold tabular-nums" style={{ fontSize: 26, color: '#e3e2e6', fontFamily: 'Geist, sans-serif' }}>{value}</p>
      <p className="font-medium mt-0.5 uppercase" style={{ fontSize: 10, color: '#bbcabf', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>{label}</p>
      {subtitle && <p className="mt-1 truncate" style={{ fontSize: 11, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>{subtitle}</p>}
    </div>
  )
}

export default function DashboardView({ history, onScan, onRescan, onViewHistory, onViewPivot, onExportReport, onExportEvidenceCsv, onExportJson, onExportDocx, loading, error, searchInputRef, onStop }) {
  const [, refreshTime] = useState(0)
  useEffect(() => {
    const id = setInterval(() => refreshTime(n => n + 1), 10000)
    return () => clearInterval(id)
  }, [])

  const [query, setQuery] = useState('')

  const totalScans   = history.length
  const threatsFound = history.filter(r => r.verdict && !['clean', 'no_data'].includes(r.verdict)).length
  const safeScans    = history.filter(r => r.verdict === 'clean').length
  const lastScan     = history[0]
  const weekAgo      = Date.now() - 7 * 86400000
  const thisWeek     = history.filter(r => (parseServerTimestamp(r.timestamp)?.getTime() ?? 0) > weekAgo).length

  function submit(fn) {
    const q = query.trim()
    if (q) fn(q)
  }

  return (
    <div className="p-6">
      {/* Search */}
      <div className="rounded mb-5 p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <div className="flex gap-3">
          <div className="relative flex-1 min-w-0">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2"
                  style={{ fontSize: 18, color: '#bbcabf', pointerEvents: 'none' }}>
              search
            </span>
            <input
              ref={searchInputRef}
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && submit(onScan)}
              type="text"
              placeholder="IP address, domain, URL, or hash…"
              className="w-full focus:outline-none transition-all"
              style={{
                background: '#1b1b1f',
                border: '1px solid #3c4a42',
                borderRadius: 2,
                padding: '10px 12px 10px 38px',
                fontSize: 13,
                color: '#e3e2e6',
                fontFamily: 'JetBrains Mono, monospace',
              }}
              onFocus={e => e.target.style.borderColor = '#4edea3'}
              onBlur={e  => e.target.style.borderColor = '#3c4a42'}
            />
          </div>
          {loading ? (
            <button
              onClick={onStop}
              className="flex items-center gap-2 transition-all active:scale-95 whitespace-nowrap shrink-0"
              style={{
                background: '#ffb4ab', color: '#690005', border: 'none', borderRadius: 2,
                padding: '10px 20px', fontSize: 12, fontWeight: 700,
                fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', cursor: 'pointer',
              }}>
              <span className="material-symbols-outlined" style={{ fontSize: 16 }}>stop</span>
              STOP
            </button>
          ) : (
            <button
              onClick={() => submit(onScan)}
              disabled={!query.trim()}
              className="flex items-center gap-2 transition-all active:scale-95 disabled:opacity-40 whitespace-nowrap shrink-0"
              style={{
                background: '#4edea3', color: '#003824', border: 'none', borderRadius: 2,
                padding: '10px 20px', fontSize: 12, fontWeight: 700,
                fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', cursor: 'pointer',
              }}>
              <span className="material-symbols-outlined" style={{ fontSize: 16 }}>radar</span>
              SCAN
            </button>
          )}
          <button
            onClick={() => submit(onRescan)}
            disabled={loading || !query.trim()}
            className="transition-all active:scale-95 disabled:opacity-40 whitespace-nowrap shrink-0"
            style={{
              background: 'transparent',
              color: '#bbcabf',
              border: '1px solid #3c4a42',
              borderRadius: 2,
              padding: '10px 18px',
              fontSize: 12,
              fontWeight: 600,
              fontFamily: 'JetBrains Mono, monospace',
              cursor: 'pointer',
            }}>
            RESCAN
          </button>
        </div>
        {error && <p className="mt-2" style={{ fontSize: 12, color: '#ffb4ab' }}>{error}</p>}
        <div className="flex gap-2 mt-3">
          {['IPv4', 'Domain', 'MD5', 'SHA256'].map(t => (
            <span key={t} className="rounded"
                  style={{ fontSize: 11, padding: '2px 10px', background: '#1b1b1f', color: '#86948a',
                           border: '1px solid #3c4a42', fontFamily: 'JetBrains Mono, monospace' }}>
              {t}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3 mb-5">
        <StatCard icon="search"         label="Total Scans"   value={totalScans}   subtitle={`+${thisWeek} this week`}         color="#4cd7f6" />
        <StatCard icon="emergency_home" label="Threats Found" value={threatsFound} subtitle="malicious or suspicious"          color="#ffb4ab" />
        <StatCard icon="verified_user"  label="Clean"         value={safeScans}    subtitle="clean indicators"                 color="#4edea3" />
        <StatCard icon="schedule"       label="Last Scan"     value={lastScan ? timeAgo(lastScan.timestamp) : '—'}
                                                               subtitle={lastScan?.indicator || 'no scans yet'}                color="#ffb95f" />
      </div>

      {/* Recent scans */}
      <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <div className="flex items-center justify-between mb-4">
          <p className="uppercase" style={{ fontSize: 11, fontWeight: 700, color: '#bbcabf', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
            Recent Scans
          </p>
        </div>
        {!history.length ? (
          <p className="py-4" style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
            No scans yet. Enter an indicator above to get started.
          </p>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: '1px solid #3c4a42' }}>
                {['Indicator', 'Type', 'Result', 'Score', 'Time'].map(h => (
                  <th key={h} className="text-left pb-2.5 pr-4 uppercase"
                      style={{ fontSize: 10, color: '#86948a', fontWeight: 600, letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>{h}</th>
                ))}
                <th />
              </tr>
            </thead>
            <tbody>
              {history.slice(0, 8).map((row, i) => (
                <tr
                  key={i}
                  style={{ borderBottom: '1px solid rgba(60,74,66,0.3)' }}
                  className="group"
                  onMouseEnter={e => e.currentTarget.style.background = '#292a2d'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td className="py-2.5 pr-4" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#e3e2e6', maxWidth: 220 }}>
                    <span className="block truncate">{row.indicator}</span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className="rounded uppercase" style={{ fontSize: 10, padding: '2px 8px', background: '#292a2d', color: '#4cd7f6', fontFamily: 'JetBrains Mono, monospace' }}>
                      {guessIndicatorType(row.indicator)}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <VerdictPill verdict={row.verdict} />
                  </td>
                  <td className="py-2.5 pr-4 tabular-nums" style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'JetBrains Mono, monospace' }}>
                    {row.score ?? '—'}
                  </td>
                  <td className="py-2.5 whitespace-nowrap" style={{ fontSize: 11, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
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
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
    </div>
  )
}