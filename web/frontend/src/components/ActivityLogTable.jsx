import { EVENT_TYPE_COLOR } from '../utils/roleColors'
import { formatTimestamp } from '../utils/time'

// Base set every self/admin view offers. Account created/deleted are
// Admin-log-only (a deleted or not-yet-existing account can't view "its own
// activity" for them) — only the Admin-facing views pass ADMIN_EVENT_TYPES.
export const BASE_EVENT_TYPES = ['Login', 'Logout', 'Scan run']
export const ADMIN_EVENT_TYPES = [...BASE_EVENT_TYPES, 'Account created', 'Account deleted']

const FIELD_STYLE = {
  background: '#1b1b1f',
  border: '1px solid #3c4a42',
  color: '#e3e2e6',
  borderRadius: 2,
  padding: '6px 10px',
  fontSize: 12,
  fontFamily: 'JetBrains Mono, monospace',
}

const TH_STYLE = {
  fontSize: 10, color: '#86948a', fontWeight: 600, letterSpacing: '0.07em',
  fontFamily: 'JetBrains Mono, monospace',
}

function EventPill({ eventType }) {
  const color = EVENT_TYPE_COLOR[eventType] || '#86948a'
  return (
    <span style={{
      background: `${color}22`, color, border: `1px solid ${color}44`,
      padding: '2px 8px', borderRadius: 2, fontSize: 10, fontWeight: 700,
      fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em',
      textTransform: 'uppercase', whiteSpace: 'nowrap',
    }}>
      {eventType}
    </span>
  )
}

/**
 * Shared table for both the global Activity Log (Admin) and a scoped
 * per-user activity history (User Detail / Analyst's own view). The caller
 * owns filter state and data fetching — this component is presentational
 * plus the filter controls' onChange wiring.
 *
 * Props:
 *   entries, total, hasMore, loading — current page of activity_log rows
 *   eventType/onEventTypeChange, dateFrom/onDateFromChange, dateTo/onDateToChange
 *   showUserColumn — false when already scoped to one user (User Detail)
 *   onUserClick(userId) — navigate to that user's User Detail view
 *   userOptions/userId/onUserChange — optional user filter dropdown (global log only)
 *   onLoadMore
 */
export default function ActivityLogTable({
  entries = [], total = 0, hasMore = false, loading = false,
  eventType = '', onEventTypeChange,
  eventTypes = BASE_EVENT_TYPES,
  dateFrom = '', onDateFromChange,
  dateTo = '', onDateToChange,
  showUserColumn = true, onUserClick,
  userOptions = null, userId = '', onUserChange,
  onLoadMore,
}) {
  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 mb-4">
        {userOptions && (
          <select value={userId} onChange={e => onUserChange?.(e.target.value)} style={FIELD_STYLE}>
            <option value="">All users</option>
            {userOptions.map(u => (
              <option key={u.id} value={u.id}>{u.name || u.email}</option>
            ))}
          </select>
        )}
        <select value={eventType} onChange={e => onEventTypeChange?.(e.target.value)} style={FIELD_STYLE}>
          <option value="">All event types</option>
          {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <label style={{ fontSize: 11, color: '#86948a', fontFamily: 'JetBrains Mono, monospace' }}>
          From{' '}
          <input type="date" value={dateFrom} onChange={e => onDateFromChange?.(e.target.value)} style={{ ...FIELD_STYLE, marginLeft: 4 }} />
        </label>
        <label style={{ fontSize: 11, color: '#86948a', fontFamily: 'JetBrains Mono, monospace' }}>
          To{' '}
          <input type="date" value={dateTo} onChange={e => onDateToChange?.(e.target.value)} style={{ ...FIELD_STYLE, marginLeft: 4 }} />
        </label>
        <span style={{ fontSize: 11, color: '#86948a', fontFamily: 'JetBrains Mono, monospace', marginLeft: 'auto' }}>
          {total} event{total === 1 ? '' : 's'}
        </span>
      </div>

      {entries.length === 0 ? (
        <p style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif', padding: '16px 0' }}>
          {loading ? 'Loading...' : 'No activity found.'}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr style={{ borderBottom: '1px solid #3c4a42' }}>
                <th className="text-left pb-2.5 pr-4 uppercase" style={TH_STYLE}>Timestamp</th>
                {showUserColumn && <th className="text-left pb-2.5 pr-4 uppercase" style={TH_STYLE}>User</th>}
                <th className="text-left pb-2.5 pr-4 uppercase" style={TH_STYLE}>Event Type</th>
                <th className="text-left pb-2.5 pr-4 uppercase" style={TH_STYLE}>Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id} style={{ borderBottom: '1px solid rgba(60,74,66,0.3)' }}>
                  <td className="py-2.5 pr-4 whitespace-nowrap" style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'JetBrains Mono, monospace' }}>
                    {formatTimestamp(e.timestamp)}
                  </td>
                  {showUserColumn && (
                    <td className="py-2.5 pr-4">
                      <button
                        onClick={() => onUserClick?.(e.user_id)}
                        disabled={!onUserClick || e.user_id == null}
                        style={{
                          background: 'transparent', border: 'none', padding: 0,
                          color: onUserClick ? '#4cd7f6' : '#e3e2e6',
                          cursor: onUserClick ? 'pointer' : 'default',
                          fontSize: 12, fontFamily: 'Geist, sans-serif', textAlign: 'left',
                          textDecoration: onUserClick ? 'underline' : 'none',
                        }}
                      >
                        {e.user_name || e.user_email}
                      </button>
                    </td>
                  )}
                  <td className="py-2.5 pr-4"><EventPill eventType={e.event_type} /></td>
                  <td className="py-2.5 pr-4" style={{ fontSize: 12, color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace' }}>
                    {e.details || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {hasMore && (
            <div style={{ textAlign: 'center', marginTop: 16 }}>
              <button
                onClick={onLoadMore}
                disabled={loading}
                style={{
                  background: 'transparent', color: '#bbcabf', border: '1px solid #3c4a42',
                  borderRadius: 2, padding: '8px 20px', fontSize: 12, fontWeight: 600,
                  fontFamily: 'JetBrains Mono, monospace', cursor: 'pointer',
                }}
              >
                {loading ? 'LOADING...' : 'LOAD MORE'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
