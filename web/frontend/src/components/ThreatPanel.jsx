export default function ThreatPanel({ threatfox, urlhaus }) {
  if (!threatfox && !urlhaus) return null

  return (
    <div className="card p-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Threat Intel</p>

      {threatfox && (
        <div className={urlhaus ? 'mb-5 pb-5 border-b border-gray-100 dark:border-[#2a2d3a]' : ''}>
          <p className="text-xs font-semibold text-indigo-500 uppercase tracking-wide mb-3">ThreatFox</p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-3">
            {threatfox.malware && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">Malware</span>
                <span className="text-gray-700 dark:text-gray-200 font-medium">{threatfox.malware}</span>
                {threatfox.malware_alias && (
                  <span className="text-xs text-gray-400 dark:text-gray-500 ml-1">({threatfox.malware_alias})</span>
                )}
              </div>
            )}
            {threatfox.threat_type && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">Threat type</span>
                <span className="text-gray-700 dark:text-gray-200">{threatfox.threat_type}</span>
              </div>
            )}
            {threatfox.confidence_level != null && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">Confidence</span>
                <div className="flex items-center gap-2 mt-0.5">
                  <div className="w-20 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full bg-orange-400 rounded-full" style={{width: `${threatfox.confidence_level}%`}} />
                  </div>
                  <span className="text-gray-700 dark:text-gray-200 text-xs">{threatfox.confidence_level}%</span>
                </div>
              </div>
            )}
            {threatfox.first_seen && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">First seen</span>
                <span className="text-gray-700 dark:text-gray-200">{threatfox.first_seen.slice(0, 10)}</span>
              </div>
            )}
            {threatfox.ioc_count != null && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">IOC count</span>
                <span className="text-gray-700 dark:text-gray-200">{threatfox.ioc_count}</span>
              </div>
            )}
          </div>
          {threatfox.tags?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {threatfox.tags.map((t, i) => (
                <span key={i} className="bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300 text-xs px-2 py-0.5 rounded">{t}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {urlhaus && (
        <div>
          <p className="text-xs font-semibold text-indigo-500 uppercase tracking-wide mb-3">URLhaus</p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-3">
            {urlhaus.threat && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">Threat type</span>
                <span className="text-gray-700 dark:text-gray-200">{urlhaus.threat}</span>
              </div>
            )}
            {urlhaus.url_count != null && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">URL count</span>
                <span className="text-gray-700 dark:text-gray-200">{urlhaus.url_count}</span>
              </div>
            )}
            {urlhaus.first_seen && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block">First seen</span>
                <span className="text-gray-700 dark:text-gray-200">{urlhaus.first_seen.slice(0, 10)}</span>
              </div>
            )}
          </div>
          {urlhaus.urls?.length > 0 && (
            <details>
              <summary className="text-xs font-medium text-gray-500 dark:text-gray-400 cursor-pointer select-none">
                Sample URLs ({urlhaus.urls.length})
              </summary>
              <div className="mt-2 overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead>
                    <tr className="text-gray-400 dark:text-gray-500 border-b border-gray-100 dark:border-[#2a2d3a]">
                      <th className="pb-1 pr-4 font-medium">URL</th>
                      <th className="pb-1 pr-4 font-medium">Status</th>
                      <th className="pb-1 font-medium">Added</th>
                    </tr>
                  </thead>
                  <tbody>
                    {urlhaus.urls.map((u, i) => (
                      <tr key={i} className="border-b border-gray-50 dark:border-[#2a2d3a] last:border-0">
                        <td className="py-1 pr-4 font-mono text-gray-600 dark:text-gray-300 max-w-xs truncate">{u.url}</td>
                        <td className="py-1 pr-4">
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            u.url_status === 'online'
                              ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-300'
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400'
                          }`}>
                            {u.url_status || '—'}
                          </span>
                        </td>
                        <td className="py-1 text-gray-500 dark:text-gray-400">{u.date_added?.slice(0, 10)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  )
}
