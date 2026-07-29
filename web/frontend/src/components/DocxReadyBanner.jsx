/**
 * Persistent "Word report ready" notification. Deliberately not a toast
 * that times out unnoticed — it stays fixed at the very top of the
 * viewport, above every view (dashboard/results/history/pivot), until the
 * user downloads the report or dismisses it explicitly.
 *
 * Props:
 *   indicator  — the indicator the report was generated for
 *   onDownload — () => downloads the .docx
 *   onDismiss  — () => closes the banner
 */
export default function DocxReadyBanner({ indicator, onDownload, onDismiss }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center justify-center flex-wrap"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 60,
        gap: 14,
        padding: '10px 20px',
        background: '#123024',
        borderBottom: '1px solid #4edea3',
        boxShadow: '0 2px 20px rgba(78,222,163,0.25)',
      }}
    >
      <span className="material-symbols-outlined" style={{ fontSize: 20, color: '#4edea3' }}>task_alt</span>
      <p style={{ fontSize: 13, color: '#e3e2e6', fontFamily: 'Geist, sans-serif', margin: 0 }}>
        Word report ready for{' '}
        <span style={{ fontFamily: 'JetBrains Mono, monospace', color: '#4edea3', fontWeight: 700 }}>
          {indicator}
        </span>
      </p>
      <button
        onClick={onDownload}
        className="transition-all active:scale-95"
        style={{
          background: '#4edea3',
          color: '#0d0e11',
          border: 'none',
          borderRadius: 2,
          padding: '6px 16px',
          fontSize: 11,
          fontWeight: 700,
          fontFamily: 'JetBrains Mono, monospace',
          letterSpacing: '0.06em',
          cursor: 'pointer',
          whiteSpace: 'nowrap',
        }}
      >
        DOWNLOAD .DOCX
      </button>
      <button
        onClick={onDismiss}
        aria-label="Dismiss"
        style={{
          background: 'transparent',
          border: 'none',
          color: '#86948a',
          cursor: 'pointer',
          fontSize: 18,
          lineHeight: 1,
          padding: 4,
        }}
        onMouseEnter={e => e.currentTarget.style.color = '#e3e2e6'}
        onMouseLeave={e => e.currentTarget.style.color = '#86948a'}
      >
        ×
      </button>
    </div>
  )
}
