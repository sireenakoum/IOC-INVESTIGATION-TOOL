import { useState, useRef, useEffect } from 'react'

/**
 * Single export button with a format picker (TXT / CSV / JSON).
 * Replaces what used to be two separate EXPORT / EXPORT CSV buttons.
 *
 * Props:
 *   indicator      — the indicator to export
 *   onExportReport — (indicator) => downloads .txt report
 *   onExportCsv    — (indicator) => downloads .csv evidence
 *   onExportJson   — (indicator) => downloads .json training data
 *   onExportDocx   — (indicator) => downloads .docx report
 *   docxDisabled   — true while the AI summary this export depends on is
 *                    still generating (or hasn't been generated yet) —
 *                    greys the DOCX option out instead of hiding it
 *   variant        — 'button' (default, VerdictCard-style) | 'inline' (compact row-action style)
 *   color          — accent color (VerdictCard passes its verdict ring color)
 */
export default function ExportMenu({ indicator, onExportReport, onExportCsv, onExportJson, onExportDocx, docxDisabled = false, variant = 'button', color = '#86948a' }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  function pick(opt) {
    if (opt.disabled) return
    setOpen(false)
    opt.fn?.(indicator)
  }

  const options = [
    { label: 'TXT REPORT',    fn: onExportReport },
    { label: 'CSV EVIDENCE',  fn: onExportCsv },
    { label: 'JSON REPORT',   fn: onExportJson },
    {
      label: 'WORD REPORT',
      fn: onExportDocx,
      disabled: docxDisabled,
      title: docxDisabled ? 'Waiting for the AI summary to finish generating' : undefined,
    },
  ].filter(o => o.fn)

  const triggerStyle = variant === 'inline'
    ? {
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
        color: '#86948a',
      }
    : {
        background: 'transparent',
        color,
        border: `1px solid ${color}66`,
        borderRadius: 2,
        padding: '10px 20px',
        fontSize: 10,
        fontWeight: 700,
        fontFamily: 'JetBrains Mono, monospace',
        letterSpacing: '0.08em',
        cursor: 'pointer',
      }

  return (
    <div ref={ref} className="relative inline-block">
      <button
        onClick={() => setOpen(o => !o)}
        className="uppercase tracking-widest transition-all active:scale-95"
        style={triggerStyle}
      >
        EXPORT {variant === 'inline' ? '' : '▾'}
      </button>

      {open && (
        <div
          className="absolute z-50 mt-1 rounded overflow-hidden"
          style={{
            right: 0,
            minWidth: 150,
            background: '#1f1f23',
            border: '1px solid #3c4a42',
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          }}
        >
          {options.map(opt => (
            <button
              key={opt.label}
              onClick={() => pick(opt)}
              disabled={opt.disabled}
              title={opt.title}
              className="w-full text-left transition-colors"
              style={{
                display: 'block',
                padding: '8px 14px',
                fontSize: 11,
                fontFamily: 'JetBrains Mono, monospace',
                letterSpacing: '0.05em',
                color: opt.disabled ? '#5a6560' : '#e3e2e6',
                background: 'transparent',
                border: 'none',
                cursor: opt.disabled ? 'not-allowed' : 'pointer',
              }}
              onMouseEnter={e => { if (!opt.disabled) e.currentTarget.style.background = '#292a2d' }}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}