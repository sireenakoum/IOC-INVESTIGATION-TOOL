const BASE_NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'scan',      label: 'Scan',      icon: 'radar'     },
  { id: 'history',   label: 'History',   icon: 'history'   },
  { id : 'pivot', label: 'Pivot Map', icon: 'pivot_table_chart'}
]

// Admin gets the full Users & Activity Log page; Analysts get a restricted
// "My Activity" view of just their own history.
const ROLE_NAV_ITEM = {
  Admin:   { id: 'users',      label: 'Users & Activity', icon: 'manage_accounts' },
  Analyst: { id: 'myActivity', label: 'My Activity',      icon: 'fact_check' },
}

export default function Sidebar({ activeView, onNavigate, collapsed, onToggleCollapse, role }) {
  const roleItem = ROLE_NAV_ITEM[role]
  const NAV_ITEMS = roleItem ? [...BASE_NAV_ITEMS, roleItem] : BASE_NAV_ITEMS

  return (
    <aside className={`fixed left-0 top-0 h-full ${collapsed ? 'w-[64px]' : 'w-[240px]'} flex flex-col z-50 select-none transition-all duration-200`}
           style={{ background: 'rgba(27,27,31,0.6)', backdropFilter: 'blur(12px)',
                    borderRight: '1px solid #3c4a42' }}>
      {/* Brand */}
      <div className={`py-8 flex items-center gap-3 ${collapsed ? 'px-0 justify-center' : 'px-6'}`}>
        <span className="material-symbols-filled text-3xl" style={{ color: '#4edea3' }}>shield</span>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="text-lg font-bold tracking-tight" style={{ color: '#4edea3', fontFamily: 'Geist, sans-serif' }}>
              IOC Investigator
            </span>
            <span className="uppercase tracking-widest" style={{ fontSize: 10, color: '#bbcabf', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono, monospace' }}>
              Threat Intelligence
            </span>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className={`flex-1 space-y-1 ${collapsed ? 'px-2' : 'px-4'}`}>
        {NAV_ITEMS.map(({ id, label, icon }) => {
          const active = activeView === id
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              title={collapsed ? label : undefined}
              className={`w-full flex items-center gap-3 py-2 rounded-lg transition-colors duration-200 text-sm
                ${collapsed ? 'px-0 justify-center' : 'px-4'}
                ${active
                  ? 'border-l-2 border-[#4edea3] bg-[#292a2d] text-[#6ffbbe]'
                  : 'text-[#bbcabf] hover:text-[#e3e2e6] hover:bg-white/5'}`}
              style={{ fontFamily: 'Geist, sans-serif' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>{icon}</span>
              {!collapsed && label}
            </button>
          )
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={onToggleCollapse}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="flex items-center justify-center py-3 text-[#bbcabf] hover:text-[#e3e2e6] hover:bg-white/5 transition-colors duration-200"
        style={{ borderTop: '1px solid #3c4a42' }}
      >
        <span className="material-symbols-outlined" style={{ fontSize: 20 }}>
          {collapsed ? 'chevron_right' : 'chevron_left'}
        </span>
      </button>

    </aside>
  )
}
