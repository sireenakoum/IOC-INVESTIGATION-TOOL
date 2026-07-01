import { useState } from 'react'

export default function SearchBar({ onScan, onRescan, loading, error }) {
  const [value, setValue] = useState('')

  function handleKey(e) {
    if (e.key === 'Enter' && value.trim()) onScan(value.trim())
  }

  return (
    <div className="card p-4 mb-6">
      <div className="flex gap-3">
        <input
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={handleKey}
          type="text"
          placeholder="IP address, domain, or hash…"
          className="flex-1 min-w-0 border border-gray-200 rounded-lg px-4 py-2.5
                     text-sm font-mono text-gray-800 placeholder-gray-400
                     focus:outline-none focus:ring-2 focus:ring-indigo-300
                     focus:border-transparent transition"
        />
        <button
          onClick={() => value.trim() && onScan(value.trim())}
          disabled={loading}
          className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm
                     font-medium px-6 py-2.5 rounded-lg disabled:opacity-50
                     disabled:cursor-not-allowed transition whitespace-nowrap"
        >
          {loading ? 'Scanning…' : 'Scan'}
        </button>
        <button
          onClick={() => value.trim() && onRescan(value.trim())}
          disabled={loading}
          className="border border-indigo-300 text-indigo-600 hover:bg-indigo-50
                     text-sm font-medium px-5 py-2.5 rounded-lg
                     disabled:opacity-50 disabled:cursor-not-allowed
                     transition whitespace-nowrap"
        >
          Rescan
        </button>
      </div>
      {error && (
        <p className="text-red-500 text-xs mt-2">{error}</p>
      )}
    </div>
  )
}
