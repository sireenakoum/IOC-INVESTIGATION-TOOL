import { useState } from 'react'
import { changePassword } from '../api/scan'

/**
 * Blocking gate shown after login when users.must_change_password is set —
 * covers the temp-password admin-create/reset-password path (see
 * web/app.py's create_user / admin_reset_password) where the admin hands
 * the user a one-time password out of band.
 */
export default function ForcePasswordChangeView({ token, currentPasswordHint, onChanged }) {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (newPassword !== confirm) {
      setError('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      await changePassword(token, currentPassword, newPassword)
      onChanged()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: '80px auto', padding: 24, background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 4 }}>
      <h2 style={{ color: '#e3e2e6', fontFamily: 'Geist, sans-serif', marginBottom: 12 }}>Change your password</h2>
      <p style={{ color: '#bbcabf', fontSize: 13, marginBottom: 16 }}>
        {currentPasswordHint || "You're using a temporary password."} Set a new one to continue.
      </p>

      <form onSubmit={handleSubmit}>
        <input
          type="password"
          placeholder="Temporary password"
          value={currentPassword}
          onChange={e => setCurrentPassword(e.target.value)}
          required
          style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
        />
        <input
          type="password"
          placeholder="New password"
          value={newPassword}
          onChange={e => setNewPassword(e.target.value)}
          required
          style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
        />
        <input
          type="password"
          placeholder="Confirm new password"
          value={confirm}
          onChange={e => setConfirm(e.target.value)}
          required
          style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
        />

        {error && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 10 }}>{error}</p>}

        <button
          type="submit"
          disabled={loading}
          style={{ width: '100%', padding: 10, background: '#4edea3', border: 'none', color: '#003824', borderRadius: 2, fontWeight: 700, cursor: 'pointer' }}
        >
          {loading ? 'Please wait...' : 'Change password'}
        </button>
      </form>
    </div>
  )
}
