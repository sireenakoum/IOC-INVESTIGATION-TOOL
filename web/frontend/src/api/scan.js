export async function fetchScan(indicator) {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchClear(indicator) {
  const res = await fetch('/api/clear', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchScanStream(indicator, onSource, onFinal, onError) {
  try {
    const res = await fetch('/api/scan/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator }),
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
    onError(e.message)
  }
}

export async function fetchResult(indicator) {
  const res = await fetch('/api/result', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({indicator}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Server error ${res.status}`)
  }
  return res.json()
}

export async function fetchHistory() {
  const res = await fetch('/api/history')
  if (!res.ok) throw new Error('Failed to load history')
  return res.json()
}
