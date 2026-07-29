import { useState, useEffect, useCallback } from 'react'
import { fetchUserDetail, fetchUserActivity, updateUserRole, updateUserStatus, resetUserPassword } from '../api/scan'
import ActivityLogTable, { ADMIN_EVENT_TYPES } from './ActivityLogTable'
import { ROLE_COLOR, STATUS_COLOR } from '../utils/roleColors'

const ROLES = ['Admin', 'Analyst']

function Field({ label, value }) {
  return (
    <div>
      <p style={{ fontSize: 10, color: '#86948a', textTransform: 'uppercase', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>{label}</p>
      <p style={{ fontSize: 13, color: '#e3e2e6', fontFamily: 'Geist, sans-serif' }}>{value ?? '—'}</p>
    </div>
  )
}

/**
 * Admin-only per-user page: profile summary + admin actions + that user's
 * full activity history. Reached by clicking a row in UsersView or an
 * Activity Log "User" link.
 */
export default function UserDetailView({ token, userId, currentUserId, onBack, onUserChanged }) {
  const [profile, setProfile] = useState(null)
  const [error, setError] = useState('')
  const [actionError, setActionError] = useState('')
  const [actionLoading, setActionLoading] = useState(false)
  const [confirmSuspend, setConfirmSuspend] = useState(false)
  const [confirmReset, setConfirmReset] = useState(false)
  const [resetResult, setResetResult] = useState(null)

  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [offset, setOffset] = useState(0)
  const [activityLoading, setActivityLoading] = useState(false)
  const [eventType, setEventType] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const loadProfile = useCallback(() => {
    fetchUserDetail(token, userId).then(setProfile).catch(e => setError(e.message))
  }, [token, userId])

  const loadActivity = useCallback((nextOffset = 0, append = false) => {
    setActivityLoading(true)
    fetchUserActivity(token, userId, { eventType, dateFrom, dateTo, offset: nextOffset, limit: 50 })
      .then(data => {
        setEntries(prev => append ? [...prev, ...data.entries] : data.entries)
        setTotal(data.total)
        setHasMore(data.has_more)
        setOffset(nextOffset + data.entries.length)
      })
      .catch(e => setError(e.message))
      .finally(() => setActivityLoading(false))
  }, [token, userId, eventType, dateFrom, dateTo])

  useEffect(() => { loadProfile() }, [loadProfile])
  useEffect(() => { loadActivity(0, false) }, [loadActivity])

  async function handleRoleChange(role) {
    setActionError('')
    setActionLoading(true)
    try {
      await updateUserRole(token, userId, role)
      loadProfile()
      onUserChanged?.()
    } catch (e) {
      setActionError(e.message)
    } finally {
      setActionLoading(false)
    }
  }

  async function handleStatusToggle() {
    const nextStatus = profile.status === 'Active' ? 'Suspended' : 'Active'
    setActionError('')
    setActionLoading(true)
    try {
      await updateUserStatus(token, userId, nextStatus)
      setConfirmSuspend(false)
      loadProfile()
      onUserChanged?.()
    } catch (e) {
      setActionError(e.message)
    } finally {
      setActionLoading(false)
    }
  }

  async function handleResetPassword() {
    setActionError('')
    setActionLoading(true)
    try {
      const res = await resetUserPassword(token, userId)
      setResetResult(res)
      setConfirmReset(false)
    } catch (e) {
      setActionError(e.message)
    } finally {
      setActionLoading(false)
    }
  }

  if (error) return <p style={{ color: '#ffb4ab', fontSize: 13, padding: 24 }}>{error}</p>
  if (!profile) return <p style={{ color: '#86948a', fontSize: 13, padding: 24 }}>Loading...</p>

  const isSelf = currentUserId != null && Number(currentUserId) === Number(userId)
  const canManage = !profile.is_bootstrap

  return (
    <div className="p-6">
      <button
        onClick={onBack}
        style={{ background: 'transparent', border: 'none', color: '#86948a', fontSize: 12, cursor: 'pointer', marginBottom: 16, fontFamily: 'JetBrains Mono, monospace' }}
      >
        ← Back to Users
      </button>

      <div className="rounded p-5 mb-6" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 style={{ fontSize: 18, color: '#e3e2e6', fontFamily: 'Geist, sans-serif', fontWeight: 700 }}>
            {profile.name || profile.email}
          </h2>
          <div className="flex items-center gap-2">
            <span style={{ background: `${ROLE_COLOR[profile.role]}22`, color: ROLE_COLOR[profile.role], border: `1px solid ${ROLE_COLOR[profile.role]}44`, padding: '2px 8px', borderRadius: 2, fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', textTransform: 'uppercase' }}>
              {profile.role}
            </span>
            <span style={{ background: `${STATUS_COLOR[profile.status]}22`, color: STATUS_COLOR[profile.status], border: `1px solid ${STATUS_COLOR[profile.status]}44`, padding: '2px 8px', borderRadius: 2, fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.07em', textTransform: 'uppercase' }}>
              {profile.status}
            </span>
            {profile.is_bootstrap && (
              <span style={{ color: '#86948a', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}>BOOTSTRAP</span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-5">
          <Field label="Email" value={profile.email} />
          <Field label="Date created" value={profile.created_at?.slice(0, 10)} />
          <Field label="Last login" value={profile.last_login ? profile.last_login.replace('T', ' ').slice(0, 16) : 'Never'} />
          <Field label="Created by" value={profile.created_by || '—'} />
        </div>

        {!canManage ? (
          <p style={{ fontSize: 12, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
            This is the bootstrap admin account — it can't be edited, suspended, or have its password reset by other admins.
          </p>
        ) : (
          <div style={{ paddingTop: 16, borderTop: '1px solid #3c4a42' }}>
            {actionError && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 10 }}>{actionError}</p>}

            <div className="flex flex-wrap items-center gap-3">
              <label style={{ fontSize: 11, color: '#86948a', fontFamily: 'JetBrains Mono, monospace' }}>
                Role{' '}
                <select
                  value={profile.role}
                  disabled={actionLoading}
                  onChange={e => handleRoleChange(e.target.value)}
                  style={{ marginLeft: 6, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2, padding: '6px 10px', fontSize: 12, fontFamily: 'JetBrains Mono, monospace' }}
                >
                  {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </label>

              {!confirmSuspend ? (
                <button
                  onClick={() => setConfirmSuspend(true)}
                  disabled={actionLoading}
                  style={{ padding: '8px 16px', background: 'transparent', border: `1px solid ${profile.status === 'Active' ? '#ffb4ab' : '#4edea3'}`, color: profile.status === 'Active' ? '#ffb4ab' : '#4edea3', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
                >
                  {profile.status === 'Active' ? 'Suspend' : 'Reactivate'}
                </button>
              ) : (
                <span className="flex items-center gap-2">
                  <span style={{ fontSize: 12, color: '#ffb4ab' }}>
                    {profile.status === 'Active' ? 'Suspend this user?' : 'Reactivate this user?'}
                  </span>
                  <button onClick={handleStatusToggle} disabled={actionLoading} style={{ padding: '6px 12px', background: '#ffb4ab', border: 'none', color: '#690005', borderRadius: 2, cursor: 'pointer', fontSize: 11, fontWeight: 700 }}>
                    Confirm
                  </button>
                  <button onClick={() => setConfirmSuspend(false)} style={{ padding: '6px 12px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 11 }}>
                    Cancel
                  </button>
                </span>
              )}

              {!confirmReset ? (
                <button
                  onClick={() => { setConfirmReset(true); setResetResult(null) }}
                  disabled={actionLoading}
                  style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
                >
                  Reset password
                </button>
              ) : (
                <span className="flex items-center gap-2">
                  <span style={{ fontSize: 12, color: '#bbcabf' }}>Reset this user's password?</span>
                  <button onClick={handleResetPassword} disabled={actionLoading} style={{ padding: '6px 12px', background: '#4edea3', border: 'none', color: '#003824', borderRadius: 2, cursor: 'pointer', fontSize: 11, fontWeight: 700 }}>
                    Confirm
                  </button>
                  <button onClick={() => setConfirmReset(false)} style={{ padding: '6px 12px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 11 }}>
                    Cancel
                  </button>
                </span>
              )}
            </div>

            {isSelf && profile.role === 'Admin' && (
              <p style={{ fontSize: 11, color: '#86948a', marginTop: 8, fontFamily: 'Geist, sans-serif' }}>
                Note: you can't demote or suspend yourself if you're the only remaining Admin.
              </p>
            )}

            {resetResult && (
              <div style={{ marginTop: 12, background: '#1b1b1f', border: '1px solid #3c4a42', borderRadius: 2, padding: 12 }}>
                {resetResult.invited ? (
                  <p style={{ fontSize: 12, color: '#4edea3' }}>Password reset link emailed to {resetResult.email}.</p>
                ) : (
                  <>
                    <p style={{ fontSize: 12, color: '#bbcabf', marginBottom: 6 }}>
                      Share this temporary password with the user — it won't be shown again.
                    </p>
                    <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: '#4edea3', wordBreak: 'break-all' }}>
                      {resetResult.temp_password}
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
        <h3 style={{ fontSize: 14, color: '#e3e2e6', fontFamily: 'Geist, sans-serif', fontWeight: 700, marginBottom: 12 }}>
          Activity History
        </h3>
        <ActivityLogTable
          entries={entries}
          total={total}
          hasMore={hasMore}
          loading={activityLoading}
          eventTypes={ADMIN_EVENT_TYPES}
          eventType={eventType} onEventTypeChange={v => { setEventType(v); setOffset(0) }}
          dateFrom={dateFrom} onDateFromChange={v => { setDateFrom(v); setOffset(0) }}
          dateTo={dateTo} onDateToChange={v => { setDateTo(v); setOffset(0) }}
          showUserColumn={false}
          onLoadMore={() => loadActivity(offset, true)}
        />
      </div>
    </div>
  )
}
