export default function OtxPanel({ otx }) {
  if (!otx) return null

  const pulses  = otx.pulses_detail?.length ? otx.pulses_detail : (otx.pulse_details || [])
  const passDns = otx.passive_dns || []
  if (!otx.pulse_count && pulses.length === 0 && passDns.length === 0) return null

  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">OTX Pulses</p>
        <div className="flex gap-3 text-xs text-gray-400 dark:text-gray-500">
          {otx.pulse_count !== undefined && (
            <span><span className="font-medium text-gray-600 dark:text-gray-300">{otx.pulse_count}</span> pulses</span>
          )}
          {otx.reputation !== undefined && otx.reputation !== 0 && (
            <span>Reputation: <span className="font-medium text-gray-600 dark:text-gray-300">{otx.reputation}</span></span>
          )}
          {otx.reputation_threat_score != null && (
            <span>Threat score: <span className="font-medium text-red-500">{otx.reputation_threat_score}</span></span>
          )}
        </div>
      </div>

      {otx.indicator_description && (
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4 italic">{otx.indicator_description}</p>
      )}

      {pulses.slice(0, 5).map((p, i) => {
        const families  = p.malware_families || p.families || []
        const attackIds = p.attack_ids || []
        const tags      = p.tags || []
        const ref       = Array.isArray(p.references) ? p.references[0] : p.ref
        return (
          <div key={i} className="mb-3 p-3 bg-gray-50 dark:bg-[#252836] rounded-lg text-sm border border-gray-100 dark:border-[#2a2d3a]">
            <p className="font-medium text-gray-800 dark:text-gray-100 mb-1">{p.name || 'Unnamed'}</p>
            {p.adversary && (
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Adversary: {p.adversary}</p>
            )}
            {families.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1">
                {families.map((m, j) => (
                  <span key={j} className="bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 text-xs px-2 py-0.5 rounded">{m}</span>
                ))}
              </div>
            )}
            {attackIds.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1">
                {attackIds.map((a, j) => (
                  <span key={j} className="bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 text-xs px-2 py-0.5 rounded font-mono">{a}</span>
                ))}
              </div>
            )}
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1">
                {tags.slice(0, 6).map((t, j) => (
                  <span key={j} className="bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300 text-xs px-2 py-0.5 rounded">{t}</span>
                ))}
              </div>
            )}
            {p.description && (
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">{p.description}</p>
            )}
            {ref && (
              <a href={ref} target="_blank" rel="noopener noreferrer"
                className="text-xs text-blue-500 hover:underline mt-1 block truncate">{ref}</a>
            )}
          </div>
        )
      })}

      {passDns.length > 0 && (
        <details className="mt-3">
          <summary className="text-xs font-medium text-gray-500 dark:text-gray-400 cursor-pointer select-none">
            Passive DNS ({passDns.length})
          </summary>
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="text-gray-400 dark:text-gray-500 border-b border-gray-100 dark:border-[#2a2d3a]">
                  <th className="pb-1 pr-4 font-medium">Hostname</th>
                  <th className="pb-1 pr-4 font-medium">Address</th>
                  <th className="pb-1 pr-4 font-medium">Type</th>
                  <th className="pb-1 pr-4 font-medium">First</th>
                  <th className="pb-1 font-medium">Last</th>
                </tr>
              </thead>
              <tbody>
                {passDns.slice(0, 20).map((r, i) => (
                  <tr key={i} className="border-b border-gray-50 dark:border-[#2a2d3a] last:border-0">
                    <td className="py-1 pr-4 font-mono text-gray-700 dark:text-gray-300">{r.hostname}</td>
                    <td className="py-1 pr-4 font-mono text-gray-700 dark:text-gray-300">{r.address}</td>
                    <td className="py-1 pr-4 text-gray-500 dark:text-gray-400">{r.record_type}</td>
                    <td className="py-1 pr-4 text-gray-500 dark:text-gray-400">{r.first}</td>
                    <td className="py-1 text-gray-500 dark:text-gray-400">{r.last}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  )
}
