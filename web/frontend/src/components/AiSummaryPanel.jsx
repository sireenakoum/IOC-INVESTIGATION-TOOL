export default function AiSummaryPanel({ loading, summary, error, scanInProgress, width = 300, onRegenerate, onStop }) {
  return (
    <aside className="fixed right-0 top-0 h-full flex flex-col overflow-y-auto z-10"
           style={{ width, background: 'rgba(27,27,31,0.6)', backdropFilter: 'blur(12px)',
                    borderLeft: '1px solid #3c4a42' }}>

      {/* Header */}
      <div className="h-16 flex items-center justify-between px-5 shrink-0" style={{ borderBottom: '1px solid #3c4a42' }}>
        <div className="flex items-center">
          <span className="material-symbols-outlined mr-2.5" style={{ fontSize: 18, color: '#4cd7f6' }}>smart_toy</span>
          <p className="uppercase" style={{ fontSize: 11, fontWeight: 700, color: '#bbcabf', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
            AI Analyst Summary
          </p>
        </div>
        {!scanInProgress && loading && (
          <button
            onClick={onStop}
            style={{ fontSize: 10, fontWeight: 600, color: '#ffb4ab', background: 'transparent',
                     border: 'none', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace',
                     letterSpacing: '0.05em', padding: 0, whiteSpace: 'nowrap' }}
            onMouseEnter={e => e.currentTarget.style.color = '#ff897d'}
            onMouseLeave={e => e.currentTarget.style.color = '#ffb4ab'}
          >
            STOP GENERATING
          </button>
        )}
        {!scanInProgress && !loading && (
          <button
            onClick={onRegenerate}
            style={{ fontSize: 10, fontWeight: 600, color: '#86948a', background: 'transparent',
                     border: 'none', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace',
                     letterSpacing: '0.05em', padding: 0, whiteSpace: 'nowrap' }}
            onMouseEnter={e => e.currentTarget.style.color = '#bbcabf'}
            onMouseLeave={e => e.currentTarget.style.color = '#86948a'}
          >
            REGENERATE
          </button>
        )}
      </div>

      <div className="p-4 space-y-4 flex-1">
        <div className="rounded p-4" style={{ background: '#1f1f23', border: '1px solid #3c4a42', minHeight: 160 }}>

          {/* Scan still running — nothing to summarize yet */}
          {scanInProgress && (
            <div className="flex flex-col items-center justify-center gap-3 py-8">
              <span className="material-symbols-outlined" style={{ fontSize: 24, color: '#86948a' }}>hourglass_empty</span>
              <p className="text-center" style={{ fontSize: 12, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
                Waiting for scan to complete…
              </p>
            </div>
          )}

          {/* Scan done, AI summary generating, no chunks yet */}
          {!scanInProgress && loading && !summary && (
            <div className="flex flex-col items-center justify-center gap-3 py-8">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ background: '#4cd7f6' }} />
                <span className="relative inline-flex rounded-full h-3 w-3" style={{ background: '#4cd7f6' }} />
              </span>
              <p className="text-center" style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'Geist, sans-serif' }}>
                Generating AI summary…
              </p>
            </div>
          )}

          {/* Error state */}
          {!scanInProgress && !loading && error && (
            <div className="flex flex-col items-center justify-center gap-2 py-6">
              <span className="material-symbols-outlined" style={{ fontSize: 22, color: '#ffb4ab' }}>error</span>
              <p className="text-center" style={{ fontSize: 12, color: '#ffb4ab', fontFamily: 'Geist, sans-serif' }}>
                Couldn't generate AI summary
              </p>
              <p className="text-center" style={{ fontSize: 11, color: '#86948a', fontFamily: 'JetBrains Mono, monospace' }}>
                {error}
              </p>
            </div>
          )}

          {/* Final summary text (shown while streaming too, regardless of loading) */}
          {!scanInProgress && !error && summary && (
            <p style={{ fontSize: 13, lineHeight: 1.6, color: '#e3e2e6', fontFamily: 'Geist, sans-serif', whiteSpace: 'pre-wrap' }}>
              {summary}
              {loading && <span className="animate-pulse">▌</span>}
            </p>
          )}

          {/* Nothing yet, nothing in flight, no error — idle default */}
          {!scanInProgress && !loading && !error && !summary && (
            <p className="text-center py-8" style={{ fontSize: 12, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
              No summary available
            </p>
          )}
        </div>
      </div>
    </aside>
  )
}
