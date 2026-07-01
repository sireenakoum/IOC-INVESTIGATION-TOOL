import { VerdictPill } from '../utils/verdict'

export default function PivotPanel({ pivot }) {
  if (!pivot) return null

  const verdicts   = pivot.pivot_verdicts || {}
  const scores     = pivot.pivot_scores   || {}
  const sourcesMap = pivot.sources_map    || {}
  const breakdown  = pivot.breakdown      || []

  if (Object.keys(verdicts).length === 0 && breakdown.length === 0) return null

  return (
    <div className="card p-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Pivot Scan</p>

      {breakdown.length > 0 && (
        <div className="mb-4">
          {breakdown.map((line, i) => (
            <p key={i} className="text-sm text-gray-600 dark:text-gray-300">{line}</p>
          ))}
        </div>
      )}

      {Object.keys(verdicts).length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="text-gray-400 dark:text-gray-500 border-b border-gray-100 dark:border-[#2a2d3a]">
                <th className="pb-1 pr-4 font-medium">IOC</th>
                <th className="pb-1 pr-4 font-medium">Verdict</th>
                <th className="pb-1 pr-4 font-medium">Score</th>
                <th className="pb-1 font-medium">Found by</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(verdicts).map(([ioc, verdict], i) => (
                <tr key={i} className="border-b border-gray-50 dark:border-[#2a2d3a] last:border-0">
                  <td className="py-1.5 pr-4 font-mono text-gray-700 dark:text-gray-300 max-w-xs truncate">{ioc}</td>
                  <td className="py-1.5 pr-4"><VerdictPill verdict={verdict} /></td>
                  <td className="py-1.5 pr-4 text-gray-600 dark:text-gray-300">{scores[ioc] ?? '—'}</td>
                  <td className="py-1.5 text-gray-500 dark:text-gray-400">
                    {(sourcesMap[ioc] || []).join(', ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
