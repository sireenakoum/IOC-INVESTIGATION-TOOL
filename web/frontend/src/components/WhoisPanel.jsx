export default function WhoisPanel({ whois, indType }) {
  if (!whois || indType !== 'domain') return null

  const fmt = (s) => (s ? s.slice(0, 10) : '—')

  return (
    <div className="card p-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">WHOIS</p>

      <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm mb-4">
        <div>
          <span className="text-xs text-gray-400 dark:text-gray-500 block">Registrar</span>
          <span className="text-gray-700 dark:text-gray-200">{whois.registrar || '—'}</span>
        </div>
        <div>
          <span className="text-xs text-gray-400 dark:text-gray-500 block">Country</span>
          <span className="text-gray-700 dark:text-gray-200">{whois.country || '—'}</span>
        </div>
        <div>
          <span className="text-xs text-gray-400 dark:text-gray-500 block">Created</span>
          <span className="text-gray-700 dark:text-gray-200">{fmt(whois.creation_date)}</span>
        </div>
        <div>
          <span className="text-xs text-gray-400 dark:text-gray-500 block">Expires</span>
          <span className="text-gray-700 dark:text-gray-200">{fmt(whois.expiration_date)}</span>
        </div>
        {whois.domain_age_days != null && (
          <div>
            <span className="text-xs text-gray-400 dark:text-gray-500 block">Domain age</span>
            <span className="text-gray-700 dark:text-gray-200">{whois.domain_age_days} days</span>
          </div>
        )}
      </div>

      {whois.privacy_masked && (
        <span className="inline-block bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300 text-xs px-2 py-0.5 rounded mb-3">
          Privacy masked
        </span>
      )}

      {whois.name_servers?.length > 0 && (
        <div>
          <span className="text-xs text-gray-400 dark:text-gray-500 block mb-1">Name servers</span>
          <div className="flex flex-wrap gap-1">
            {whois.name_servers.slice(0, 6).map((ns, i) => (
              <span key={i} className="bg-gray-100 dark:bg-[#252836] text-gray-600 dark:text-gray-300 text-xs px-2 py-0.5 rounded font-mono">
                {ns}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
