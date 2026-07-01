import { useState, useEffect } from 'react'
import VerdictCard from './VerdictCard'
import SourceGrid from './SourceGrid'
import BreakdownPanel from './BreakdownPanel'
import { getSourceContainers } from './SourceCard'

const SOURCE_ORDER = [
  'vt', 'otx', 'abuse', 'shodan', 'censys',
  'whois', 'threatfox', 'urlhaus', 'greynoise',
  'urlscan', 'hybrid', 'google_intel', 'spamhaus_drop',
  'pivot',
]

export default function ResultsView({ result, partial = {}, scanIndicator = '', onScan, onRescan, loading, error }) {
  const [query, setQuery] = useState(result?.indicator ?? scanIndicator)

  useEffect(() => {
    setQuery(result?.indicator ?? scanIndicator)
  }, [result?.indicator, scanIndicator])

  function submit(fn) {
    const q = query.trim()
    if (q) fn(q)
  }

  return (
    <div className="p-6 max-w-5xl">

      {/* Search bar */}
      <div className="rounded p-4 mb-5 flex gap-3" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <div className="relative flex-1 min-w-0">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2"
                style={{ fontSize: 18, color: '#bbcabf', pointerEvents: 'none' }}>search</span>
          <input
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
              padding: '9px 12px 9px 38px',
              fontSize: 13,
              color: '#e3e2e6',
              fontFamily: 'JetBrains Mono, monospace',
            }}
            onFocus={e => e.target.style.borderColor = '#4edea3'}
            onBlur={e  => e.target.style.borderColor = '#3c4a42'}
          />
        </div>
        <button
          onClick={() => submit(onScan)}
          disabled={loading || !query.trim()}
          className="flex items-center gap-2 transition-all active:scale-95 disabled:opacity-40 whitespace-nowrap shrink-0"
          style={{
            background: '#4edea3', color: '#003824', border: 'none', borderRadius: 2,
            padding: '9px 18px', fontSize: 12, fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', cursor: 'pointer',
          }}>
          <span className="material-symbols-outlined" style={{ fontSize: 16 }}>radar</span>
          {loading ? 'SCANNING…' : 'SCAN'}
        </button>
        <button
          onClick={() => submit(onRescan)}
          disabled={loading || !query.trim()}
          className="transition-all active:scale-95 disabled:opacity-40 whitespace-nowrap shrink-0"
          style={{
            background: 'transparent', color: '#bbcabf', border: '1px solid #3c4a42', borderRadius: 2,
            padding: '9px 16px', fontSize: 12, fontWeight: 600,
            fontFamily: 'JetBrains Mono, monospace', cursor: 'pointer',
          }}>
          RESCAN
        </button>
      </div>

      {error && <p className="mb-3" style={{ fontSize: 12, color: '#ffb4ab' }}>{error}</p>}

      {/* Verdict card */}
      {result && <div className="mb-5"><VerdictCard result={result} /></div>}

      {/* Streaming indicator */}
      {loading && !result && (
        <div className="rounded p-4 mb-5 flex items-center gap-3" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ background: '#4edea3' }} />
            <span className="relative inline-flex rounded-full h-2 w-2" style={{ background: '#4edea3' }} />
          </span>
          <span style={{ fontSize: 13, color: '#bbcabf', fontFamily: 'Geist, sans-serif' }}>
            Scanning… {Object.keys(partial).length} / 12 sources complete
          </span>
        </div>
      )}

      {/* Sources + Breakdown */}
      <div className="flex flex-col gap-4 mb-5">
        <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
          <p className="uppercase mb-3"
             style={{ fontSize: 10, fontWeight: 700, color: '#bbcabf', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
            Threat Intel Matrix
          </p>
          <SourceGrid perSource={result?.per_source} partial={partial} loading={loading && !result} />
        </div>
        {result
          ? <BreakdownPanel breakdown={result.breakdown} />
          : <div className="rounded skeleton-shimmer" style={{ border: '1px solid #3c4a42', minHeight: 120 }} />
        }
      </div>

      {/* Source detail cards */}
      <div className="space-y-3">
        {SOURCE_ORDER.map(key => {
          const data = result?.[key] ?? partial?.[key]
          if (!data) return null
          const containers = getSourceContainers(key, data)
          return containers.map((container, i) => (
            <div key={`${key}-${i}`} style={{ animation: 'fadeSlideIn 0.25s ease forwards' }}>
              {container}
            </div>
          ))
        })}
      </div>
    </div>
  )
}
