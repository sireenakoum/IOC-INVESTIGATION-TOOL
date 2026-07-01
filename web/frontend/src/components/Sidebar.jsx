const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'scan',      label: 'Scan',      icon: 'radar'     },
  { id: 'history',   label: 'History',   icon: 'history'   },
]

export default function Sidebar({ activeView, onNavigate }) {
  return (
    <aside className="fixed left-0 top-0 h-full w-[280px] flex flex-col z-50 select-none"
           style={{ background: 'rgba(27,27,31,0.6)', backdropFilter: 'blur(12px)',
                    borderRight: '1px solid #3c4a42' }}>
      {/* Brand */}
      <div className="px-6 py-8 flex items-center gap-3">
        <span className="material-symbols-filled text-3xl" style={{ color: '#4edea3' }}>shield</span>
        <div className="flex flex-col">
          <span className="text-lg font-bold tracking-tight" style={{ color: '#4edea3', fontFamily: 'Geist, sans-serif' }}>
            IOC Investigator
          </span>
          <span className="uppercase tracking-widest" style={{ fontSize: 10, color: '#bbcabf', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono, monospace' }}>
            Threat Intelligence
          </span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-4 space-y-1">
        {NAV_ITEMS.map(({ id, label, icon }) => {
          const active = activeView === id
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg transition-colors duration-200 text-sm
                ${active
                  ? 'border-l-2 border-[#4edea3] bg-[#292a2d] text-[#6ffbbe]'
                  : 'text-[#bbcabf] hover:text-[#e3e2e6] hover:bg-white/5'}`}
              style={{ fontFamily: 'Geist, sans-serif' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>{icon}</span>
              {label}
            </button>
          )
        })}
      </nav>

    </aside>
  )
}
