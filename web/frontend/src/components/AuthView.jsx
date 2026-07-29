import { useState } from 'react'
import { signup, login } from '../api/scan'

export default function AuthView({ onLoggedIn }) {
  const [mode, setMode] = useState('login') // 'login' or 'signup'
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [signupDone, setSignupDone] = useState(false) // true once signup succeeds, before verification

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (mode === 'signup') {
        await signup(name, email, password)
        setSignupDone(true)
      } else {
        const result = await login(email, password)
        onLoggedIn(result.token, result.email)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // After a successful signup, tell the person to go verify their email
  // before they can log in — the backend won't issue a session token until
  // is_verified is true, so there's nothing to log them into yet.
  if (signupDone) {
    return (
      <div style={{ maxWidth: 420, margin: '80px auto', padding: 24, background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 4 }}>
        <h2 style={{ color: '#e3e2e6', fontFamily: 'Geist, sans-serif', marginBottom: 12 }}>Check your email</h2>
        <p style={{ color: '#bbcabf', fontSize: 13, marginBottom: 16 }}>
          We sent a verification link to <strong style={{ color: '#e3e2e6' }}>{email}</strong>.
          Click the link in that email to activate your account, then come back here to log in.
        </p>
        <p style={{ color: '#86948a', fontSize: 12, marginBottom: 20 }}>
          Didn't get it? Check your spam folder, or make sure the email address was typed correctly.
        </p>
        <button
          onClick={() => { setSignupDone(false); setMode('login'); setPassword(''); setName('') }}
          style={{ display: 'block', width: '100%', padding: '10px', background: '#4edea3', border: 'none', color: '#003824', borderRadius: 2, fontWeight: 700, cursor: 'pointer' }}
        >
          Back to login
        </button>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 420, margin: '80px auto', padding: 24, background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 4 }}>
      <h2 style={{ color: '#e3e2e6', fontFamily: 'Geist, sans-serif', marginBottom: 20 }}>
        {mode === 'login' ? 'Log In' : 'Sign Up'}
      </h2>

      <form onSubmit={handleSubmit}>
        {mode === 'signup' && (
          <input
            type="text"
            placeholder="Name"
            value={name}
            onChange={e => setName(e.target.value)}
            required
            style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
          />
        )}
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          style={{ width: '100%', padding: 10, marginBottom: 10, background: '#1b1b1f', border: '1px solid #3c4a42', color: '#e3e2e6', borderRadius: 2 }}
        />

        {error && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 10 }}>{error}</p>}

        <button
          type="submit"
          disabled={loading}
          style={{ width: '100%', padding: 10, background: '#4edea3', border: 'none', color: '#003824', borderRadius: 2, fontWeight: 700, cursor: 'pointer' }}
        >
          {loading ? 'Please wait...' : mode === 'login' ? 'Log In' : 'Sign Up'}
        </button>
      </form>

      <p style={{ marginTop: 16, fontSize: 12, color: '#86948a', textAlign: 'center' }}>
        {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
        <span
          onClick={() => { setMode(mode === 'login' ? 'signup' : 'login'); setError('') }}
          style={{ color: '#4cd7f6', cursor: 'pointer' }}
        >
          {mode === 'login' ? 'Sign up' : 'Log in'}
        </span>
      </p>
    </div>
  )
}