import { useState, useEffect, useCallback } from 'react'
import { fetchUsers, fetchActivityLog, updateUserRole, updateUserStatus, resetUserPassword } from '../api/scan'
import UserDetailView from './UserDetailView'
import CreateUserModal from './CreateUserModal'
import ActivityLogTable, { ADMIN_EVENT_TYPES } from './ActivityLogTable'
import { ROLE_COLOR, STATUS_COLOR } from '../utils/roleColors'

const ROLES = ['Admin', 'Analyst']

const TH_STYLE = {
  fontSize: 10, color: '#86948a', fontWeight: 600, letterSpacing: '0.07em',
  fontFamily: 'JetBrains Mono, monospace',
}

const ACTION_BTN = {
  fontSize: 10, fontFamily: 'JetBrains Mono, monospace', padding: '3px 10px',
  background: 'transparent', border: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
}

function Pill({ label, color }) {
  return (
    <span style={{
      background: `${color}22`, color, border: `1px solid ${color}44`,
      padding: '2px 8px', borderRadius: 2, fontSize: 10, fontWeight: 700,
      fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', textTransform: 'uppercase',
    }}>
      {label}
    </span>
  )
}

function UserRow({ user, token, currentUserId, onOpen, onChanged, onNotice }) {
  const [busy, setBusy] = useState(false)
  const [confirmSuspend, setConfirmSuspend] = useState(false)
  const canManage = !user.is_bootstrap

  async function changeRole(role) {
    setBusy(true)
    try {
      await updateUserRole(token, user.id, role)
      onChanged()
    } catch (e) {
      onNotice({ type: 'error', text: e.message })
    } finally {
      setBusy(false)
    }
  }

  async function toggleStatus() {
    const next = user.status === 'Active' ? 'Suspended' : 'Active'
    setBusy(true)
    try {
      await updateUserStatus(token, user.id, next)
      setConfirmSuspend(false)
      onChanged()
    } catch (e) {
      onNotice({ type: 'error', text: e.message })
    } finally {
      setBusy(false)
    }
  }

  async function resetPassword() {
    setBusy(true)
    try {
      const res = await resetUserPassword(token, user.id)
      onNotice({
        type: 'success',
        text: res.invited
          ? `Password reset link emailed to ${res.email}.`
          : `Temp password for ${res.email}: ${res.temp_password} (won't be shown again)`,
      })
    } catch (e) {
      onNotice({ type: 'error', text: e.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <tr style={{ borderBottom: '1px solid rgba(60,74,66,0.3)' }} className="group">
      <td className="py-2.5 pr-4">
        <button onClick={() => onOpen(user.id)} style={{ background: 'transparent', border: 'none', padding: 0, cursor: 'pointer', color: '#e3e2e6', fontSize: 13, fontFamily: 'Geist, sans-serif', textAlign: 'left' }}>
          {user.name || '(no name)'}
        </button>
      </td>
      <td className="py-2.5 pr-4" style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'JetBrains Mono, monospace' }}>{user.email}</td>
      <td className="py-2.5 pr-4">
        {canManage ? (
          <select
            value={user.role}
            disabled={busy}
            onChange={e => changeRole(e.target.value)}
            style={{ background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2, padding: '3px 6px', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
          >
            {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        ) : (
          <Pill label={user.role} color={ROLE_COLOR[user.role]} />
        )}
      </td>
      <td className="py-2.5 pr-4"><Pill label={user.status} color={STATUS_COLOR[user.status]} /></td>
      <td className="py-2.5 pr-4" style={{ fontSize: 11, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>{user.created_at?.slice(0, 10)}</td>
      <td className="py-2.5 pr-4" style={{ fontSize: 11, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
        {user.last_login ? user.last_login.replace('T', ' ').slice(0, 16) : 'Never'}
      </td>
      <td className="py-2.5 pl-2">
        {!canManage ? (
          <span style={{ fontSize: 10, color: '#86948a', fontFamily: 'JetBrains Mono, monospace' }}>BOOTSTRAP</span>
        ) : (
          <div className="opacity-0 group-hover:opacity-100 transition-opacity" style={{ display: 'inline-flex' }}>
            {!confirmSuspend ? (
              <button onClick={() => setConfirmSuspend(true)} disabled={busy} style={{ ...ACTION_BTN, color: user.status === 'Active' ? '#ffb4ab' : '#4edea3', borderRight: '1px solid #3c4a42' }}>
                {user.status === 'Active' ? 'SUSPEND' : 'REACTIVATE'}
              </button>
            ) : (
              <>
                <button onClick={toggleStatus} disabled={busy} style={{ ...ACTION_BTN, color: '#ffb4ab', borderRight: '1px solid #3c4a42' }}>CONFIRM</button>
                <button onClick={() => setConfirmSuspend(false)} style={{ ...ACTION_BTN, color: '#86948a', borderRight: '1px solid #3c4a42' }}>CANCEL</button>
              </>
            )}
            <button onClick={resetPassword} disabled={busy} style={{ ...ACTION_BTN, color: '#4cd7f6' }}>RESET PW</button>
          </div>
        )}
      </td>
    </tr>
  )
}

/**
 * Admin-facing "Users & Activity Log" page: a Users tab (list + row
 * actions + create), an Activity Log tab (global, filterable), and a
 * User Detail drill-down reachable from either. Analysts get a separate,
 * much smaller MyActivityView instead — see App.jsx's role-based routing.
 */
export default function UsersView({ token, currentUserId }) {
  const [tab, setTab] = useState('users') // 'users' | 'activity'
  const [selectedUserId, setSelectedUserId] = useState(null)
  const [users, setUsers] = useState([])
  const [usersError, setUsersError] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [notice, setNotice] = useState(null)

  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [offset, setOffset] = useState(0)
  const [activityLoading, setActivityLoading] = useState(false)
  const [eventType, setEventType] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [filterUserId, setFilterUserId] = useState('')

  const loadUsers = useCallback(() => {
    fetchUsers(token).then(data => setUsers(data.users)).catch(e => setUsersError(e.message))
  }, [token])

  const loadActivity = useCallback((nextOffset = 0, append = false) => {
    setActivityLoading(true)
    fetchActivityLog(token, { eventType, dateFrom, dateTo, userId: filterUserId, offset: nextOffset, limit: 50 })
      .then(data => {
        setEntries(prev => append ? [...prev, ...data.entries] : data.entries)
        setTotal(data.total)
        setHasMore(data.has_more)
        setOffset(nextOffset + data.entries.length)
      })
      .catch(e => setUsersError(e.message))
      .finally(() => setActivityLoading(false))
  }, [token, eventType, dateFrom, dateTo, filterUserId])

  useEffect(() => { loadUsers() }, [loadUsers])
  useEffect(() => { if (tab === 'activity') loadActivity(0, false) }, [tab, loadActivity])

  useEffect(() => {
    if (!notice) return
    const t = setTimeout(() => setNotice(null), 8000)
    return () => clearTimeout(t)
  }, [notice])

  if (selectedUserId != null) {
    return (
      <UserDetailView
        token={token}
        userId={selectedUserId}
        currentUserId={currentUserId}
        onBack={() => setSelectedUserId(null)}
        onUserChanged={loadUsers}
      />
    )
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 style={{ fontSize: 20, color: '#e3e2e6', fontFamily: 'Geist, sans-serif', fontWeight: 700 }}>
          Users & Activity Log
        </h2>
        {tab === 'users' && (
          <button
            onClick={() => setShowCreate(true)}
            style={{ background: '#4edea3', color: '#003824', border: 'none', borderRadius: 2, padding: '8px 16px', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', cursor: 'pointer' }}
          >
            + CREATE USER
          </button>
        )}
      </div>

      <div className="flex gap-1 mb-4" style={{ borderBottom: '1px solid #3c4a42' }}>
        {[['users', 'Users'], ['activity', 'Activity Log']].map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            style={{
              padding: '8px 16px', background: 'transparent', border: 'none', cursor: 'pointer',
              fontSize: 12, fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, letterSpacing: '0.05em',
              color: tab === id ? '#4edea3' : '#86948a',
              borderBottom: tab === id ? '2px solid #4edea3' : '2px solid transparent',
            }}
          >
            {label.toUpperCase()}
          </button>
        ))}
      </div>

      {usersError && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 12 }}>{usersError}</p>}
      {notice && (
        <p style={{ color: notice.type === 'error' ? '#ffb4ab' : '#4edea3', fontSize: 12, marginBottom: 12, wordBreak: 'break-word' }}>
          {notice.text}
        </p>
      )}

      <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        {tab === 'users' ? (
          users.length === 0 ? (
            <p style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>No users yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr style={{ borderBottom: '1px solid #3c4a42' }}>
                    {['Name', 'Email', 'Role', 'Status', 'Date created', 'Last login'].map(h => (
                      <th key={h} className="text-left pb-2.5 pr-4 uppercase" style={TH_STYLE}>{h}</th>
                    ))}
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <UserRow
                      key={u.id}
                      user={u}
                      token={token}
                      currentUserId={currentUserId}
                      onOpen={setSelectedUserId}
                      onChanged={loadUsers}
                      onNotice={setNotice}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (
          <ActivityLogTable
            entries={entries}
            total={total}
            hasMore={hasMore}
            loading={activityLoading}
            eventTypes={ADMIN_EVENT_TYPES}
            eventType={eventType} onEventTypeChange={v => { setEventType(v); setOffset(0) }}
            dateFrom={dateFrom} onDateFromChange={v => { setDateFrom(v); setOffset(0) }}
            dateTo={dateTo} onDateToChange={v => { setDateTo(v); setOffset(0) }}
            userOptions={users}
            userId={filterUserId} onUserChange={v => { setFilterUserId(v); setOffset(0) }}
            onUserClick={setSelectedUserId}
            onLoadMore={() => loadActivity(offset, true)}
          />
        )}
      </div>

      {showCreate && (
        <CreateUserModal
          token={token}
          onClose={() => setShowCreate(false)}
          onCreated={loadUsers}
        />
      )}
    </div>
  )
}
