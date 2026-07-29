import { useState } from 'react'
import { createUser } from '../api/scan'

const FIELD_STYLE = {
  width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f',
  border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2,
}

export default function CreateUserModal({ token, onClose, onCreated }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('Analyst')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null) // response from create_user, shown once

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await createUser(token, { name, email, role })
      setResult(res)
      onCreated?.()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.6)', zIndex: 200,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        style={{ maxWidth: 440, width: '90%', padding: 24, background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 4 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ color: '#e3e2e6', fontFamily: 'Geist, sans-serif', margin: 0, fontSize: 18 }}>Create User</h2>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#86948a', fontSize: 20, cursor: 'pointer' }}>×</button>
        </div>

        {result ? (
          <div>
            <p style={{ fontSize: 13, color: '#4edea3', marginBottom: 12 }}>
              {result.invited ? `Invite email sent to ${result.email}.` : `Account created for ${result.email}.`}
            </p>
            {!result.invited && result.temp_password && (
              <>
                <p style={{ fontSize: 12, color: '#bbcabf', marginBottom: 6 }}>
                  Email sending isn't configured, so share this temporary password with them directly.
                  It won't be shown again, and they'll be required to change it on first login.
                </p>
                <div style={{ background: '#1b1b1f', border: '1px solid #3c4a42', borderRadius: 2, padding: 12, wordBreak: 'break-all', fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: '#4edea3', marginBottom: 12 }}>
                  {result.temp_password}
                </div>
              </>
            )}
            <button
              onClick={onClose}
              style={{ width: '100%', padding: 10, background: '#4edea3', border: 'none', color: '#003824', borderRadius: 2, fontWeight: 700, cursor: 'pointer' }}
            >
              Done
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <input type="text" placeholder="Full name" value={name} onChange={e => setName(e.target.value)} required style={FIELD_STYLE} />
            <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} required style={FIELD_STYLE} />
            <select value={role} onChange={e => setRole(e.target.value)} style={FIELD_STYLE}>
              <option value="Admin">Admin</option>
              <option value="Analyst">Analyst</option>
            </select>

            {error && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 10 }}>{error}</p>}

            <button
              type="submit"
              disabled={loading}
              style={{ width: '100%', padding: 10, background: '#4edea3', border: 'none', color: '#003824', borderRadius: 2, fontWeight: 700, cursor: 'pointer' }}
            >
              {loading ? 'Creating...' : 'Create user'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
