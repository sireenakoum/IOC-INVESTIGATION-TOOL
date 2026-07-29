import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { VERDICT_COLOR } from '../utils/verdictColors'

const VERDICT_LABEL = {
  high:        'High Risk',
  medium_risk: 'Medium Risk',
  low_risk:    'Low Risk',
  suspicious:  'Suspicious',
  clean:       'Clean',
  no_data:     'Unknown',
}

export default function RightPanel({ history, verdictCounts = {}, width = 300 }) {
  const last5          = history.slice(0, 5)
  const highRiskCount  = last5.filter(r => ['high', 'medium_risk'].includes(r.verdict)).length
  const threatLevel    = highRiskCount >= 3 ? 'High' : highRiskCount >= 1 ? 'Medium' : 'Low'
  const threatColor    = threatLevel === 'High' ? VERDICT_COLOR.high : threatLevel === 'Medium' ? VERDICT_COLOR.medium_risk : VERDICT_COLOR.clean
  const barPct         = threatLevel === 'High' ? 85 : threatLevel === 'Medium' ? 50 : 15

  // verdictCounts is aggregated server-side over the user's FULL history
  // (see /api/history's verdict_counts), not just whatever page of rows
  // happens to be loaded client-side — so every category present shows up
  // with its true total, independent of ledger pagination.
  const donutData = Object.entries(verdictCounts).map(([v, n]) => ({
    name:  VERDICT_LABEL[v] || v,
    value: n,
    color: VERDICT_COLOR[v] || '#3c4a42',
  }))

  return (
    <aside className="fixed right-0 top-0 h-full flex flex-col overflow-y-auto z-10"
           style={{ width, background: 'rgba(27,27,31,0.6)', backdropFilter: 'blur(12px)',
                    borderLeft: '1px solid #3c4a42' }}>

      {/* Header */}
      <div className="h-16 flex items-center px-5 shrink-0" style={{ borderBottom: '1px solid #3c4a42' }}>
        <span className="material-symbols-outlined mr-2.5" style={{ fontSize: 18, color: '#4cd7f6' }}>analytics</span>
        <p className="uppercase" style={{ fontSize: 11, fontWeight: 700, color: '#bbcabf', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
          Intel Summary
        </p>
      </div>

      <div className="p-4 space-y-4 flex-1">

        {/* Threat level gauge */}
        <div className="rounded p-4" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
          <p className="uppercase mb-2" style={{ fontSize: 10, fontWeight: 600, color: '#86948a', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
            Global Threat Level
          </p>
          <div className="flex items-center gap-2 mb-3">
            <span className="font-bold" style={{ fontSize: 22, color: threatColor, fontFamily: 'Geist, sans-serif' }}>
              {threatLevel}
            </span>
            {threatLevel !== 'Low' && (
              <span className="material-symbols-outlined pulse-danger" style={{ fontSize: 18, color: threatColor }}>
                emergency_home
              </span>
            )}
          </div>
          <div className="relative mt-1.5 mb-1.5">
            <div className="h-1.5 rounded-full"
                 style={{ background: `linear-gradient(to right, ${VERDICT_COLOR.clean}, ${VERDICT_COLOR.medium_risk}, ${VERDICT_COLOR.high})` }} />
            <div className="absolute top-1/2 -translate-y-1/2 w-3 h-3 rounded-full"
                 style={{ left: `${barPct}%`, transform: 'translate(-50%, -50%)',
                          background: 'white', border: `2.5px solid ${threatColor}`,
                          boxShadow: '0 1px 4px rgba(0,0,0,0.4)' }} />
          </div>
          {!history.length && (
            <p style={{ fontSize: 11, color: '#86948a', marginTop: 8, fontFamily: 'Geist, sans-serif' }}>No scan data yet</p>
          )}
          {highRiskCount > 0 && (
            <p style={{ fontSize: 11, color: '#86948a', marginTop: 8, fontFamily: 'Geist, sans-serif' }}>
              Increased activity in last {Math.min(5, history.length)} scans
            </p>
          )}
        </div>

        {/* Donut chart */}
        <div className="rounded p-4" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
          <p className="uppercase mb-3" style={{ fontSize: 10, fontWeight: 700, color: '#bbcabf', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace' }}>
            Verdict Distribution
          </p>
          {donutData.length ? (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={donutData} cx="50%" cy="50%"
                       innerRadius={38} outerRadius={60}
                       paddingAngle={2} dataKey="value" strokeWidth={0}>
                    {donutData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 2, fontSize: 12, color: '#e3e2e6' }}
                    itemStyle={{ color: '#e3e2e6' }}
                    cursor={false}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-1">
                {donutData.map((d, i) => (
                  <div key={i} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full shrink-0" style={{ background: d.color }} />
                      <span style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'Geist, sans-serif' }}>{d.name}</span>
                    </div>
                    <span className="tabular-nums font-semibold" style={{ fontSize: 12, color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace' }}>
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-center py-6" style={{ fontSize: 12, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>No scan data yet</p>
          )}
        </div>
      </div>
    </aside>
  )
}
