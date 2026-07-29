import { useState } from 'react'
import { acceptInvite } from '../api/scan'

/**
 * Landing page for both the admin-invite link and the admin-triggered
 * "reset password" email link (see web/app.py's accept_invite route —
 * both hand out the same kind of one-time token). Read from the URL's
 * ?invite= query param by App.jsx before the user is known to be logged in.
 */
export default function AcceptInviteView({ token, onAccepted }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      const result = await acceptInvite(token, password)
      onAccepted(result.token, result.email)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: '80px auto', padding: 24, background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 4 }}>
      <h2 style={{ color: '#e3e2e6', fontFamily: 'Geist, sans-serif', marginBottom: 12 }}>Set your password</h2>
      <p style={{ color: '#bbcabf', fontSize: 13, marginBottom: 16 }}>
        Choose a password to activate your IOC Investigator account.
      </p>

      <form onSubmit={handleSubmit}>
        <input
          type="password"
          placeholder="New password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
        />
        <input
          type="password"
          placeholder="Confirm password"
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
          {loading ? 'Please wait...' : 'Activate account'}
        </button>
      </form>
    </div>
  )
}
