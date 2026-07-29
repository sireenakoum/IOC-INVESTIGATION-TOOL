import { useState, useEffect } from 'react'
import { fetchMeWithKey, regenerateApiKey, deleteAccount } from '../api/scan'

export default function AccountPanel({ token, onClose, onLogout, onAccountDeleted }) {
  const [account, setAccount] = useState(null)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [regenerating, setRegenerating] = useState(false)
  const [confirmRegen, setConfirmRegen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [deleteConfirmText, setDeleteConfirmText] = useState('')

  useEffect(() => {
    fetchMeWithKey(token)
      .then(setAccount)
      .catch(e => setError(e.message))
  }, [token])

  function handleCopy() {
    navigator.clipboard.writeText(account.api_key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  async function handleRegenerate() {
    setRegenerating(true)
    setError('')
    try {
      const result = await regenerateApiKey(token)
      setAccount(prev => ({ ...prev, api_key: result.api_key }))
      setConfirmRegen(false)
    } catch (e) {
      setError(e.message)
    } finally {
      setRegenerating(false)
    }
  }

  async function handleDelete() {
    setDeleting(true)
    setError('')
    try {
      await deleteAccount(token)
      onAccountDeleted()
    } catch (e) {
      setError(e.message)
      setDeleting(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.6)', zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        style={{ maxWidth: 460, width: '90%', padding: 24, background: '#1f1f23', border: '1px solid #3c4a42', borderRadius: 4 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ color: '#e3e2e6', fontFamily: 'Geist, sans-serif', margin: 0 }}>Account</h2>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#86948a', fontSize: 20, cursor: 'pointer' }}>×</button>
        </div>

        {error && <p style={{ color: '#ffb4ab', fontSize: 12, marginBottom: 12 }}>{error}</p>}

        {!account ? (
          <p style={{ color: '#86948a', fontSize: 13 }}>Loading...</p>
        ) : (
          <>
            <div style={{ marginBottom: 16 }}>
              <p style={{ fontSize: 11, color: '#86948a', textTransform: 'uppercase', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>Email</p>
              <p style={{ fontSize: 13, color: '#e3e2e6' }}>{account.email}</p>
            </div>

            <div style={{ marginBottom: 16 }}>
              <p style={{ fontSize: 11, color: '#86948a', textTransform: 'uppercase', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>API Key</p>
              <div style={{ background: '#1b1b1f', border: '1px solid #3c4a42', borderRadius: 2, padding: 12, wordBreak: 'break-all', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#4edea3', marginBottom: 8 }}>
                {account.api_key}
              </div>
              <button
                onClick={handleCopy}
                style={{ padding: '6px 14px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noopener noreferrer"
                style={{ display: 'inline-block', marginLeft: 8, padding: '6px 14px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, fontSize: 12, textDecoration: 'none' }}
              >
                View API docs
              </a>
            </div>

            <div style={{ marginBottom: 16 }}>
              {!confirmRegen ? (
                <button
                  onClick={() => setConfirmRegen(true)}
                  style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #ffb4ab', color: '#ffb4ab', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
                >
                  Regenerate key
                </button>
              ) : (
                <div>
                  <p style={{ fontSize: 12, color: '#ffb4ab', marginBottom: 8 }}>
                    This will invalidate your current key immediately. Anything using it will stop working. Continue?
                  </p>
                  <button
                    onClick={handleRegenerate}
                    disabled={regenerating}
                    style={{ padding: '8px 16px', background: '#ffb4ab', border: 'none', color: '#690005', borderRadius: 2, cursor: 'pointer', fontSize: 12, fontWeight: 700, marginRight: 8 }}
                  >
                    {regenerating ? 'Regenerating...' : 'Yes, regenerate'}
                  </button>
                  <button
                    onClick={() => setConfirmRegen(false)}
                    style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>

            <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid #3c4a42' }}>
              <button
                onClick={onLogout}
                style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 12, marginRight: 8 }}
              >
                Log out
              </button>
            </div>

            <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid #3c4a42' }}>
              <p style={{ fontSize: 11, color: '#86948a', textTransform: 'uppercase', letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace', marginBottom: 8 }}>
                Irreversible
              </p>
              {!confirmDelete ? (
                <button
                  onClick={() => setConfirmDelete(true)}
                  style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #b91c1c', color: '#b91c1c', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
                >
                  Delete account
                </button>
              ) : (
                <div>
                  <p style={{ fontSize: 12, color: '#ffb4ab', marginBottom: 8 }}>
                    This permanently deletes your account, your API key, and your entire scan history.
                    This cannot be undone. Type <strong>DELETE</strong> to confirm.
                  </p>
                  <input
                    type="text"
                    value={deleteConfirmText}
                    onChange={e => setDeleteConfirmText(e.target.value)}
                    placeholder="Type DELETE"
                    style={{ width: '100%', padding: 8, marginBottom: 8, background: '#1b1b1f', border: '1px solid #b91c1c', color: '#e3e2e6', borderRadius: 2, fontFamily: 'JetBrains Mono, monospace' }}
                  />
                  <button
                    onClick={handleDelete}
                    disabled={deleting || deleteConfirmText !== 'DELETE'}
                    style={{
                      padding: '8px 16px',
                      background: deleteConfirmText === 'DELETE' ? '#b91c1c' : '#3c4a42',
                      border: 'none',
                      color: '#fff',
                      borderRadius: 2,
                      cursor: deleteConfirmText === 'DELETE' ? 'pointer' : 'not-allowed',
                      fontSize: 12,
                      fontWeight: 700,
                      marginRight: 8,
                    }}
                  >
                    {deleting ? 'Deleting...' : 'Permanently delete account'}
                  </button>
                  <button
                    onClick={() => { setConfirmDelete(false); setDeleteConfirmText('') }}
                    style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #3c4a42', color: '#bbcabf', borderRadius: 2, cursor: 'pointer', fontSize: 12 }}
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}