export default function InfraPanel({ shodan, censys }) {
  if (!shodan && !censys) return null

  const sources = []
  if (shodan) sources.push({ label: 'Shodan', data: shodan })
  if (censys) sources.push({ label: 'Censys', data: censys })

  return (
    <div className="card p-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
        Infrastructure
        {sources.length > 1
          ? <span className="ml-2 normal-case font-normal text-gray-500">(Shodan + Censys)</span>
          : <span className="ml-2 normal-case font-normal text-gray-500">({sources[0].label})</span>
        }
      </p>

      {sources.map(({ label, data }) => {
        const ports    = data.ports    || []
        const services = data.services || []
        const vulns    = data.vulns    || []
        const hosts    = data.hostnames || []

        return (
          <div key={label} className={
            sources.length > 1
              ? 'mb-5 pb-5 border-b border-gray-100 dark:border-[#2a2d3a] last:mb-0 last:pb-0 last:border-0'
              : ''
          }>
            {sources.length > 1 && (
              <p className="text-xs font-semibold text-indigo-500 uppercase tracking-wide mb-2">{label}</p>
            )}

            <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-3">
              {data.org     && <div><span className="text-xs text-gray-400 dark:text-gray-500 block">Org</span><span className="text-gray-700 dark:text-gray-200 truncate block">{data.org}</span></div>}
              {data.asn     && <div><span className="text-xs text-gray-400 dark:text-gray-500 block">ASN</span><span className="text-gray-700 dark:text-gray-200">{data.asn}</span></div>}
              {data.country && <div><span className="text-xs text-gray-400 dark:text-gray-500 block">Country</span><span className="text-gray-700 dark:text-gray-200">{data.country}</span></div>}
              {data.os      && <div><span className="text-xs text-gray-400 dark:text-gray-500 block">OS</span><span className="text-gray-700 dark:text-gray-200">{data.os}</span></div>}
            </div>

            {ports.length > 0 && (
              <div className="mb-3">
                <span className="text-xs text-gray-400 dark:text-gray-500 block mb-1">Open ports</span>
                <div className="flex flex-wrap gap-1">
                  {ports.slice(0, 20).map((p, i) => (
                    <span key={i} className="bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 text-xs px-2 py-0.5 rounded font-mono">{p}</span>
                  ))}
                </div>
              </div>
            )}

            {services.length > 0 && (
              <details className="mb-3">
                <summary className="text-xs font-medium text-gray-500 dark:text-gray-400 cursor-pointer select-none">
                  Services ({services.length})
                </summary>
                <div className="mt-2 overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead>
                      <tr className="text-gray-400 dark:text-gray-500 border-b border-gray-100 dark:border-[#2a2d3a]">
                        <th className="pb-1 pr-4 font-medium">Port</th>
                        <th className="pb-1 pr-4 font-medium">Proto</th>
                        <th className="pb-1 pr-4 font-medium">Product</th>
                        <th className="pb-1 font-medium">Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {services.map((s, i) => (
                        <tr key={i} className="border-b border-gray-50 dark:border-[#2a2d3a] last:border-0">
                          <td className="py-1 pr-4 font-mono text-gray-700 dark:text-gray-300">{s.port}</td>
                          <td className="py-1 pr-4 text-gray-500 dark:text-gray-400">{s.transport}</td>
                          <td className="py-1 pr-4 text-gray-600 dark:text-gray-300">{s.product || '—'}</td>
                          <td className="py-1 text-gray-500 dark:text-gray-400">{s.version || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            )}

            {vulns.length > 0 && (
              <div className="mb-3">
                <span className="text-xs text-gray-400 dark:text-gray-500 block mb-1">CVEs ({vulns.length})</span>
                <div className="flex flex-wrap gap-1">
                  {vulns.map((v, i) => (
                    <span key={i} className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-300 text-xs px-2 py-0.5 rounded font-mono">{v}</span>
                  ))}
                </div>
              </div>
            )}

            {hosts.length > 0 && (
              <div>
                <span className="text-xs text-gray-400 dark:text-gray-500 block mb-1">Hostnames</span>
                <div className="flex flex-wrap gap-1">
                  {hosts.slice(0, 8).map((h, i) => (
                    <span key={i} className="bg-gray-100 dark:bg-[#252836] text-gray-600 dark:text-gray-300 text-xs px-2 py-0.5 rounded font-mono">{h}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
