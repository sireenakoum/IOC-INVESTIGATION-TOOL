import { guessIndicatorType } from '../utils/indicatorType'
import { VERDICT_COLOR, VERDICT_COLOR_RGB } from '../utils/verdictColors'

export default function Header({ scanIndicator, threatActive, authEmail, onOpenAccount }) {
  return (
    <header className="h-16 flex items-center justify-between px-8 shrink-0 z-40"
            style={{ background: 'rgba(18,19,22,0.8)', backdropFilter: 'blur(8px)',
                     borderBottom: '1px solid #3c4a42' }}>

      {/* Left: breadcrumb / context */}
      <div className="flex items-center gap-4 flex-1">
        {scanIndicator ? (
          <>
            <span className="material-symbols-outlined text-[#bbcabf]" style={{ fontSize: 18 }}>radar</span>
            <span className="font-mono text-sm" style={{ color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace' }}>
              {scanIndicator}
            </span>
            <span className="uppercase rounded" style={{ fontSize: 10, padding: '2px 10px', color: '#bbcabf',
                                                           border: '1px solid #3c4a42', letterSpacing: '0.08em',
                                                           fontFamily: 'JetBrains Mono, monospace' }}>
              {guessIndicatorType(scanIndicator)}
            </span>
            {threatActive && (
              <div className="flex items-center gap-1.5 px-3 py-1 rounded"
                   style={{ background: `rgba(${VERDICT_COLOR_RGB.high}, 0.15)`, border: `1px solid rgba(${VERDICT_COLOR_RGB.high}, 0.4)` }}>
                <span className="material-symbols-outlined pulse-danger" style={{ fontSize: 14, color: VERDICT_COLOR.high }}>emergency_home</span>
                <span className="uppercase" style={{ fontSize: 10, color: VERDICT_COLOR.high, letterSpacing: '0.08em', fontFamily: 'JetBrains Mono, monospace' }}>
                  Active Threat Detected
                </span>
              </div>
            )}
          </>
        ) : null}
      </div>

      {/* Right: account */}
      {onOpenAccount && (
        <button
          onClick={onOpenAccount}
          className="flex items-center gap-2 rounded transition-colors"
          style={{
            background: 'transparent',
            border: '1px solid #3c4a42',
            borderRadius: 2,
            padding: '6px 12px',
            cursor: 'pointer',
          }}
          onMouseEnter={e => e.currentTarget.style.background = '#1f1f23'}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 16, color: '#bbcabf' }}>
            settings
          </span>
          <span style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'JetBrains Mono, monospace' }}>
            {authEmail || 'Account'}
          </span>
        </button>
      )}

    </header>
  )
}