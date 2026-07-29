export async function fetchScan(apiKey, indicator) {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json',
      'X-API-Key': apiKey,
    },
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchClear(apiKey, indicator) {
  const res = await fetch('/api/clear', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchClearCache(apiKey, indicator) {
  const res = await fetch('/api/cache/clear', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchScanStream(apiKey, indicator, onSource, onFinal, onError, signal) {
  try {
    const res = await fetch('/api/scan/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json','X-API-Key': apiKey, },
      body: JSON.stringify({ indicator }),
      signal,
    })

    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || `Server error ${res.status}`)
    }

    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop()
      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed) continue
        try {
          const msg = JSON.parse(trimmed)
          if (msg.type === 'source') onSource(msg.key, msg.data)
          if (msg.type === 'final')  onFinal(msg)
        } catch (e) {
          console.warn('Failed to parse stream chunk:', trimmed)
        }
      }
    }

    if (buffer.trim()) {
      try {
        const msg = JSON.parse(buffer.trim())
        if (msg.type === 'source') onSource(msg.key, msg.data)
        if (msg.type === 'final')  onFinal(msg)
      } catch {}
    }
  } catch (e) {
    if (e.name === 'AbortError') return
    onError(e.message)
  }
}

export async function fetchResult(apiKey, indicator) {
  const res = await fetch('/api/result', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchPivotStatus(apiKey, indicator) {
  const res = await fetch('/api/pivot/status', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchReport(apiKey, indicator) {
  const res = await fetch('/api/report', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchReportCsv(apiKey, indicator) {
  const res = await fetch('/api/report/csv', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchReportJson(apiKey, indicator) {
  const res = await fetch('/api/report/digest', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchReportDocx(apiKey, indicator) {
  const res = await fetch('/api/report/docx', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    // Error responses are still JSON (HTTPException detail) even though a
    // successful response is a binary docx.
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.blob()
}

export async function fetchGenerateReportDocx(apiKey, indicator) {
  const res = await fetch('/api/report/docx/generate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchDownloadReportDocx(apiKey, token) {
  const res = await fetch('/api/report/docx/download', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({token}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.blob()
}

export async function fetchAiSummary(apiKey, indicator) {
  const res = await fetch('/api/report/ai-summary', {
    method: 'POST',
    headers: {'Content-Type': 'application/json','X-API-Key': apiKey,},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchAiSummaryStream(apiKey, indicator, onChunk, onDone, onError, signal) {
  try {
    const res = await fetch('/api/report/ai-summary/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' ,'X-API-Key': apiKey,},
      body: JSON.stringify({ indicator }),
      signal,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || `Server error ${res.status}`)
    }
    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let full = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      full += decoder.decode(value, { stream: true })
      onChunk(full)
    }
    onDone(full)
  } catch (e) {
    if (e.name === 'AbortError') return
    onError(e.message)
  }
}

export async function fetchHistory(token, offset = 0, limit = 50) {
  const res = await fetch(`/api/history?offset=${offset}&limit=${limit}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('Failed to load history')
  return res.json()
}

export async function signup(name, email, password) {
  const res = await fetch('/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function login(email, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchMe(token) {
  const res = await fetch('/api/auth/me', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}
export async function fetchMeWithKey(token) {
  const res = await fetch('/api/auth/me', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function regenerateApiKey(token) {
  const res = await fetch('/api/auth/regenerate-key', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}
export async function deleteAccount(token) {
  const res = await fetch('/api/auth/delete-account', {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function logout(token) {
  const res = await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function acceptInvite(token, password) {
  const res = await fetch('/api/auth/accept-invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, password }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function changePassword(authToken, currentPassword, newPassword) {
  const res = await fetch('/api/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

// ── Admin: users ─────────────────────────────────────────────────────────

export async function fetchUsers(token) {
  const res = await fetch('/api/admin/users', {
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchUserDetail(token, userId) {
  const res = await fetch(`/api/admin/users/${userId}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function createUser(token, { name, email, role }) {
  const res = await fetch('/api/admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ name, email, role }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function updateUserRole(token, userId, role) {
  const res = await fetch(`/api/admin/users/${userId}/role`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ role }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function updateUserStatus(token, userId, status) {
  const res = await fetch(`/api/admin/users/${userId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ status }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function resetUserPassword(token, userId) {
  const res = await fetch(`/api/admin/users/${userId}/reset-password`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

// ── Activity log ─────────────────────────────────────────────────────────

function _activityQuery({ eventType, dateFrom, dateTo, userId, offset = 0, limit = 50 } = {}) {
  const params = new URLSearchParams({ offset, limit })
  if (eventType) params.set('event_type', eventType)
  if (dateFrom)  params.set('date_from', dateFrom)
  if (dateTo)    params.set('date_to', dateTo)
  if (userId)    params.set('user_id', userId)
  return params.toString()
}

export async function fetchActivityLog(token, filters) {
  const res = await fetch(`/api/admin/activity?${_activityQuery(filters)}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchUserActivity(token, userId, filters) {
  const res = await fetch(`/api/admin/users/${userId}/activity?${_activityQuery(filters)}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchMyActivity(token, filters) {
  const res = await fetch(`/api/activity/me?${_activityQuery(filters)}`, {
    headers: { 'Authorization': `Bearer ${token}` },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}