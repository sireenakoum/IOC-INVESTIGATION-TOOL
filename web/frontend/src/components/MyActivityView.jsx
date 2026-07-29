import { useState, useEffect, useCallback } from 'react'
import { fetchMyActivity } from '../api/scan'
import ActivityLogTable from './ActivityLogTable'
import { ROLE_COLOR } from '../utils/roleColors'

/**
 * Restricted equivalent of UserDetailView for Analysts: "view own activity"
 * per ROLES_&_PRIVILEGES, without the Users list or any admin actions —
 * GET /api/activity/me is scoped server-side to the caller regardless of
 * what's passed here, so there's no user-selection UI to build.
 */
export default function MyActivityView({ token, email, name, role }) {
  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [eventType, setEventType] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const load = useCallback((nextOffset = 0, append = false) => {
    setLoading(true)
    fetchMyActivity(token, { eventType, dateFrom, dateTo, offset: nextOffset, limit: 50 })
      .then(data => {
        setEntries(prev => append ? [...prev, ...data.entries] : data.entries)
        setTotal(data.total)
        setHasMore(data.has_more)
        setOffset(nextOffset + data.entries.length)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [token, eventType, dateFrom, dateTo])

  useEffect(() => { load(0, false) }, [load])

  return (
    <div className="p-6">
      <h2 style={{ fontSize: 20, color: '#e3e2e6', fontFamily: 'Geist, sans-serif', fontWeight: 700, marginBottom: 16 }}>
        My Activity
      </h2>

      <div className="rounded p-5 mb-6" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <div className="flex items-center gap-3">
          <p style={{ fontSize: 13, color: '#e3e2e6', fontFamily: 'Geist, sans-serif' }}>{name || email}</p>
          <span style={{ background: `${ROLE_COLOR[role]}22`, color: ROLE_COLOR[role], border: `1px solid ${ROLE_COLOR[role]}44`, padding: '2px 8px', borderRadius: 2, fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', textTransform: 'uppercase' }}>
            {role}
          </span>
        </div>
      </div>

      {error && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 12 }}>{error}</p>}

      <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <ActivityLogTable
          entries={entries}
          total={total}
          hasMore={hasMore}
          loading={loading}
          eventType={eventType} onEventTypeChange={v => { setEventType(v); setOffset(0) }}
          dateFrom={dateFrom} onDateFromChange={v => { setDateFrom(v); setOffset(0) }}
          dateTo={dateTo} onDateToChange={v => { setDateTo(v); setOffset(0) }}
          showUserColumn={false}
          onLoadMore={() => load(offset, true)}
        />
      </div>
    </div>
  )
}
