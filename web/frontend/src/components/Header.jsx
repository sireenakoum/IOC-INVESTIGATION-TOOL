export default function Header({ scanIndicator, threatActive }) {
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
            {threatActive && (
              <div className="flex items-center gap-1.5 px-3 py-1 rounded"
                   style={{ background: 'rgba(147,0,10,0.2)', border: '1px solid rgba(255,180,171,0.3)' }}>
                <span className="material-symbols-outlined pulse-danger" style={{ fontSize: 14, color: '#ffb4ab' }}>emergency_home</span>
                <span className="uppercase" style={{ fontSize: 10, color: '#ffb4ab', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono, monospace' }}>
                  Active Threat Detected
                </span>
              </div>
            )}
          </>
        ) : null}
      </div>

    </header>
  )
}
