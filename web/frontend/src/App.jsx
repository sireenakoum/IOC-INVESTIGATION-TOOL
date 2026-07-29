import { useState, useEffect, useRef } from 'react'
import { fetchScanStream, fetchClear, fetchClearCache, fetchResult, fetchHistory, fetchReport, fetchReportCsv, fetchReportJson, fetchReportDocx, fetchAiSummaryStream, fetchGenerateReportDocx, fetchDownloadReportDocx, fetchMe, logout as apiLogout } from './api/scan'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import DashboardView from './components/DashboardView'
import ResultsView from './components/ResultsView'
import RightPanel from './components/RightPanel'
import AiSummaryPanel from './components/AiSummaryPanel'
import DocxReadyBanner from './components/DocxReadyBanner'
import HistoryTable from './components/HistoryTable'
import PivotVisualization from './components/PivotVisualization'
import AuthView from './components/AuthView'
import AccountPanel from './components/AccountPanel'
import AcceptInviteView from './components/AcceptInviteView'
import ForcePasswordChangeView from './components/ForcePasswordChangeView'
import UsersView from './components/UsersView'
import MyActivityView from './components/MyActivityView'

// Stopgap for surviving a page refresh without introducing real routing:
// the current view (and whatever indicator it's showing) is mirrored into
// sessionStorage and re-read on mount. This makes refresh/back-button
// behave, but there's still no shareable URL for a specific page or
// detail view — that would require an actual router, which is out of
// scope for this change.
const VIEW_STORAGE_KEY = 'iocViewState'

function readSavedView() {
  try {
    const raw = sessionStorage.getItem(VIEW_STORAGE_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

const savedView = readSavedView()

export default function App() {
  const [result,        setResult]        = useState(null)
  const [partial,       setPartial]       = useState({})
  const [scanIndicator, setScanIndicator] = useState(savedView?.scanIndicator || '')
  const [history,       setHistory]       = useState([])
  const [loading,       setLoading]       = useState(false)
  const [stopped,       setStopped]       = useState(false)
  const [error,         setError]         = useState('')
  const [view,          setView]          = useState(savedView?.view || 'dashboard')
  const [pivotIndicator, setPivotIndicator] = useState(savedView?.pivotIndicator || '')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const stored = localStorage.getItem('sidebarCollapsed')
    return stored === null ? true : stored === 'true'
  })
  const [aiSummary,        setAiSummary]        = useState('')
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false)
  const [aiSummaryError,   setAiSummaryError]   = useState('')
  // { indicator, token, filename } | null — survives navigating to another
  // view on purpose, so the "report ready" banner stays unmissable even if
  // the user has moved on to History/Dashboard/etc. by the time it's ready.
  const [docxReady, setDocxReady] = useState(null)
  const [panelWidth, setPanelWidth] = useState(300)
  const isResizingPanel = useRef(false)
  const searchInputRef      = useRef(null)
  const abortControllerRef  = useRef(null)
  const aiSummaryAbortControllerRef = useRef(null)
  const displayedIndicatorRef = useRef('')
  const [ledgerRows,   setLedgerRows]   = useState([])
  const [ledgerOffset, setLedgerOffset] = useState(0)
  const [ledgerHasMore, setLedgerHasMore] = useState(false)
  const [verdictCounts, setVerdictCounts] = useState({})
  const [ledgerLoading, setLedgerLoading] = useState(false)
  const ledgerLoadingRef = useRef(false)
  const ledgerOffsetRef = useRef(0)
  const [authToken, setAuthToken] = useState(() => localStorage.getItem('authToken'))
  const [authEmail, setAuthEmail] = useState('')
  const [authName, setAuthName] = useState('')
  const [authRole, setAuthRole] = useState(null)
  const [authUserId, setAuthUserId] = useState(null)
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [apiKey, setApiKey] = useState(null)
  const [authChecked, setAuthChecked] = useState(false)
  const [showAccountPanel, setShowAccountPanel] = useState(false)

  // Admin-invite / admin-reset-password links land here as ?invite=TOKEN
  // (see web/app.py's send_invite_email) — read once on first mount, before
  // the user is known to be logged in, and strip it from the URL so a
  // later reload doesn't re-trigger the accept-invite screen.
  const [inviteToken] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    const t = params.get('invite')
    if (t) window.history.replaceState({}, '', window.location.pathname)
    return t
  })

  useEffect(() => {
    if (!authToken) {
      setAuthChecked(true)
      return
    }
    fetchMe(authToken)
      .then(data => {
        setAuthEmail(data.email)
        setAuthName(data.name || '')
        setAuthRole(data.role)
        setAuthUserId(data.user_id)
        setMustChangePassword(!!data.must_change_password)
        setApiKey(data.api_key)
        setAuthChecked(true)
      })
      .catch(() => {
        localStorage.removeItem('authToken')
        setAuthToken(null)
        setApiKey(null)
        setAuthChecked(true)
      })
  }, [authToken])

  useEffect(() => {
    if (!authToken) return
    fetchHistory(authToken).then(data => {
      setHistory(data.entries)
      setVerdictCounts(data.verdict_counts || {})
    }).catch(() => {})
  }, [authToken])

  // Keep the persisted view in sync so a refresh restores it (see
  // readSavedView above).
  useEffect(() => {
    sessionStorage.setItem(VIEW_STORAGE_KEY, JSON.stringify({ view, scanIndicator, pivotIndicator }))
  }, [view, scanIndicator, pivotIndicator])

  // One-time restore of the view's data on load: the view/indicator itself
  // is already restored via useState above, but the actual result/ledger
  // data behind it still needs fetching once we have credentials.
  const didRestoreRef = useRef(false)
  useEffect(() => {
    if (didRestoreRef.current || !apiKey) return
    didRestoreRef.current = true
    if (view === 'results' && scanIndicator) {
      handleViewHistory(scanIndicator)
    } else if (view === 'history') {
      loadLedger(0, false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiKey])

  // A restored view may no longer be allowed for this user (e.g. an
  // admin-only page saved before a role change) — fall back to the
  // default view rather than restoring into a now-blocked page.
  useEffect(() => {
    if (!authChecked) return
    if (view === 'users' && authRole !== 'Admin') {
      setView('dashboard')
    } else if (view === 'myActivity' && authRole !== 'Analyst') {
      setView('dashboard')
    }
  }, [authChecked, authRole, view])

  // Browser-level nav (refresh, close tab, back/forward, typing a URL) can't be
  // hard-blocked by a web app — this only triggers the browser's native
  // "leave site?" confirm while a scan or AI summary generation is in flight,
  // same as any unsaved-work warning. Removed as soon as both finish/stop.
  useEffect(() => {
    if (!loading && !aiSummaryLoading) return
    const handler = (e) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [loading, aiSummaryLoading])

  function startPanelResize(e) {
    e.preventDefault()
    isResizingPanel.current = true
    document.body.style.cursor = 'ew-resize'
    document.body.style.userSelect = 'none'
  }

  useEffect(() => {
    function onMouseMove(e) {
      if (!isResizingPanel.current) return
      const newWidth = window.innerWidth - e.clientX
      const clamped = Math.min(500, Math.max(240, newWidth))
      setPanelWidth(clamped)
    }
    function onMouseUp() {
      if (!isResizingPanel.current) return
      isResizingPanel.current = false
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }
  }, [])

  function handleLoggedIn(token, email) {
    localStorage.setItem('authToken', token)
    setAuthToken(token)
    setAuthEmail(email)
  }

  function handleLogout() {
    // Best-effort: records the Logout activity event server-side. The
    // token is discarded client-side regardless of whether this succeeds
    // (e.g. it had already expired) — see web/app.py's /api/auth/logout.
    if (authToken) apiLogout(authToken).catch(() => {})
    localStorage.removeItem('authToken')
    sessionStorage.removeItem(VIEW_STORAGE_KEY)
    setAuthToken(null)
    setAuthEmail('')
    setAuthName('')
    setAuthRole(null)
    setAuthUserId(null)
    setMustChangePassword(false)
    setApiKey(null)
    setDocxReady(null)
    // So a fresh login in the same tab (no page reload) also lands on the
    // default view, not wherever this session happened to be.
    setView('dashboard')
    setScanIndicator('')
    setPivotIndicator('')
    setResult(null)
  }

  async function generateAiSummary(indicator) {
    const isDisplayed = () => displayedIndicatorRef.current === indicator
    if (isDisplayed()) {
      setAiSummaryLoading(true)
      setAiSummaryError('')
      setAiSummary('')
    }
    // A fresh generation is starting — any previously-shown "report ready"
    // banner refers to a now-superseded summary, so clear it. A new one
    // reappears once (if) this run completes.
    setDocxReady(null)
    aiSummaryAbortControllerRef.current?.abort()
    const controller = new AbortController()
    aiSummaryAbortControllerRef.current = controller
    await fetchAiSummaryStream(
      apiKey,
      indicator,
      (partial) => { if (isDisplayed()) setAiSummary(partial) },
      () => {
        if (isDisplayed()) setAiSummaryLoading(false)
        // Only fires on a genuine full completion (aborted/errored runs
        // never reach onDone), so this is exactly "once the full text is
        // generated" — convert it to a .docx automatically.
        triggerDocxGeneration(indicator)
      },
      (msg) => { if (isDisplayed()) { setAiSummaryError(msg); setAiSummaryLoading(false) } },
      controller.signal,
    )
  }

  async function triggerDocxGeneration(indicator) {
    try {
      const { token, filename } = await fetchGenerateReportDocx(apiKey, indicator)
      setDocxReady({ indicator, token, filename })
    } catch (e) {
      // Non-fatal: the AI summary itself already finished and is visible
      // (and still manually exportable via the Export menu). Auto-docx
      // generation failing shouldn't block or stick anything in a
      // "generating" state — just skip the ready-banner for this run.
      console.error('Auto docx generation failed:', e.message)
    }
  }

  function handleDismissDocxReady() {
    setDocxReady(null)
  }

  async function handleDownloadReadyDocx() {
    if (!docxReady) return
    try {
      const blob = await fetchDownloadReportDocx(apiKey, docxReady.token)
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = docxReady.filename
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message)
    }
  }

  async function loadLedger(offset = 0, append = false) {
    if (append && ledgerLoadingRef.current) return
    ledgerLoadingRef.current = true
    setLedgerLoading(true)
    try {
      const data = await fetchHistory(authToken, offset, 50)
      setLedgerRows(prev => append ? [...prev, ...data.entries] : data.entries)
      // Only the first page reflects "most recent scans" — a Load More
      // page is an older slice and must not clobber the recent-scans /
      // verdict-distribution state derived from `history`.
      if (!append) setHistory(data.entries)
      setVerdictCounts(data.verdict_counts || {})
      const nextOffset = offset + data.entries.length
      setLedgerOffset(nextOffset)
      ledgerOffsetRef.current = nextOffset
      setLedgerHasMore(data.has_more)
    } catch (e) {
      setError(e.message)
    } finally {
      setLedgerLoading(false)
      ledgerLoadingRef.current = false
    }
  }

  function handleLoadMoreHistory() {
    loadLedger(ledgerOffsetRef.current, true)
  }

  async function handleScan(indicator) {
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller

    setLoading(true)
    setStopped(false)
    setError('')
    setResult(null)
    setPartial({})
    setScanIndicator(indicator)
    displayedIndicatorRef.current = indicator
    setView('results')
    setAiSummary('')
    setAiSummaryError('')
    setAiSummaryLoading(false)

    await fetchScanStream(
      apiKey,
      indicator,
      (key, data) => {
        if (displayedIndicatorRef.current === indicator) {
          setPartial(prev => ({ ...prev, [key]: data }))
        }
      },
      (data) => {
        if (displayedIndicatorRef.current === indicator) {
          setResult(data)
          setPartial({})
          setLoading(false)
        }
        fetchHistory(authToken).then(d => { setHistory(d.entries); setVerdictCounts(d.verdict_counts || {}) }).catch(() => {})
        generateAiSummary(indicator)
      },
      (msg) => {
        if (displayedIndicatorRef.current === indicator) {
          setError(msg)
          setLoading(false)
        }
      },
      controller.signal,
    )
  }

  async function handleRescan(indicator) {
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller

    setLoading(true)
    setStopped(false)
    setError('')
    setResult(null)
    setPartial({})
    setScanIndicator(indicator)
    displayedIndicatorRef.current = indicator
    setView('results')
    setAiSummary('')
    setAiSummaryError('')
    setAiSummaryLoading(false)

    try {
      await fetchClearCache(apiKey, indicator)
    } catch (e) {
      if (displayedIndicatorRef.current === indicator) {
        setError(e.message)
        setLoading(false)
      }
      return
    }

    await fetchScanStream(
      apiKey,
      indicator,
      (key, data) => {
        if (displayedIndicatorRef.current === indicator) {
          setPartial(prev => ({ ...prev, [key]: data }))
        }
      },
      (data) => {
        if (displayedIndicatorRef.current === indicator) {
          setResult(data)
          setPartial({})
          setLoading(false)
        }
        fetchHistory(authToken).then(d => { setHistory(d.entries); setVerdictCounts(d.verdict_counts || {}) }).catch(() => {})
        generateAiSummary(indicator)
      },
      (msg) => {
        if (displayedIndicatorRef.current === indicator) {
          setError(msg)
          setLoading(false)
        }
      },
      controller.signal,
    )
  }

  async function handleStopScan() {
    abortControllerRef.current?.abort()
    setLoading(false)
    setPartial({})
    setStopped(true)

    // The scan never finished, so `result` is still whatever it was before
    // this scan started (null, for Scan/Rescan). Fall back to the last
    // successfully saved result for this indicator, which the backend
    // preserves until a rescan actually completes.
    const indicator = scanIndicator
    if (indicator) {
      try {
        const data = await fetchResult(apiKey, indicator)
        setResult(data)
        setAiSummary(data.ai_summary || '')
      } catch (e) {
        // No previously saved result exists (e.g. first scan ever for this
        // indicator was stopped) — genuinely nothing to fall back to.
      }
    }
  }

  async function handleViewHistory(indicator) {
    setLoading(true)
    setStopped(false)
    setError('')
    setResult(null)
    setPartial({})
    setScanIndicator(indicator)
    displayedIndicatorRef.current = indicator
    setView('results')
    setAiSummary('')
    setAiSummaryError('')
    setAiSummaryLoading(false)
    try {
      const data = await fetchResult(apiKey, indicator)
      if (displayedIndicatorRef.current === indicator) {
        setResult(data)
        setAiSummary(data.ai_summary || '')
        setAiSummaryError('')
        setAiSummaryLoading(false)
      }
    } catch (e) {
      if (displayedIndicatorRef.current === indicator) {
        setError(e.message)
      }
    } finally {
      if (displayedIndicatorRef.current === indicator) {
        setLoading(false)
      }
    }
  }

  function handleRegenerateAiSummary() {
    if (scanIndicator) generateAiSummary(scanIndicator)
  }

  function handleStopAiSummary() {
    aiSummaryAbortControllerRef.current?.abort()
    setAiSummaryLoading(false)
  }

  function handleViewPivot(indicator) {
    setPivotIndicator(indicator)
    setView('pivot')
  }

  async function handleDeleteHistory(indicator) {
    if (!window.confirm(`Delete all scan history for "${indicator}"? This cannot be undone.`)) {
      return
    }
    try {
      await fetchClear(apiKey, indicator)
      loadLedger(0, false)
      if (scanIndicator === indicator) {
        setResult(null)
        setScanIndicator('')
        setView('history')
      }
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleExportReport(indicator) {
    try {
      const { report } = await fetchReport(apiKey, indicator)
      const blob = new Blob([report], { type: 'text/plain' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `${indicator.replace(/[^a-z0-9._-]/gi, '_')}-report.txt`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleExportEvidenceCsv(indicator) {
    try {
      const { csv } = await fetchReportCsv(apiKey, indicator)
      const blob = new Blob([csv], { type: 'text/csv' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `${indicator.replace(/[^a-z0-9._-]/gi, '_')}-evidence.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleExportJson(indicator) {
    try {
      const data = await fetchReportJson(apiKey, indicator)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `${indicator.replace(/[^a-z0-9._-]/gi, '_')}-training.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleExportDocx(indicator) {
    try {
      const blob = await fetchReportDocx(apiKey, indicator)
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `${indicator.replace(/[^a-z0-9._-]/gi, '_')}-report.docx`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message)
    }
  }

  async function handleExportHistoryCsv() {
    let allRows = []
    let offset = 0
    let hasMore = true

    try {
      while (hasMore) {
        const data = await fetchHistory(authToken, offset, 100)
        allRows = [...allRows, ...data.entries]
        offset += data.entries.length
        hasMore = data.has_more
      }
    } catch (e) {
      setError(e.message)
      return
    }

    const headers = ['Indicator', 'Verdict', 'Score', 'Timestamp']
    const rows = allRows.map(r => [r.indicator, r.verdict, r.score ?? '', r.timestamp])
    const escape = v => `"${String(v).replace(/"/g, '""')}"`
    const csv = [headers, ...rows].map(row => row.map(escape).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `ioc-history-${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  function handleNavigate(id) {
    // Lock is whichever of the two existing busy flags is active — a scan
    // (`loading`) and AI summary generation (`aiSummaryLoading`) never run
    // at once (the latter only starts once the former finishes), so at most
    // one of these messages applies at a time.
    if (loading || aiSummaryLoading) {
      const message = loading
        ? 'A scan is still running. Leaving this page will stop it. Stop scan and leave?'
        : 'The AI summary is still generating. Leaving this page will stop generating the report. Stop generating and leave?'
      const leave = window.confirm(message)
      if (!leave) return
      if (loading) handleStopScan()
      if (aiSummaryLoading) handleStopAiSummary()
    }
    if (id === 'scan') {
      setView('dashboard')
      setTimeout(() => searchInputRef.current?.focus(), 50)
    } else if (id === 'history') {
      setView('history')
      loadLedger(0, false)
    } else if (id === 'dashboard') {
      setResult(null)
      setView('dashboard')
    } else if (id === 'pivot') {
      setPivotIndicator(scanIndicator)
      setView('pivot')
    } else if (id === 'users' || id === 'myActivity') {
      setView(id)
    }
  }

  const activeNav   = view === 'results' ? 'scan' : view
  const threatActive = result && ['high', 'medium_risk'].includes(result.verdict)
  // `stopped` should only suppress the in-progress (loading/partial) display —
  // once a result is restored (from a completed scan or from history after a
  // Stop), it must still be shown rather than hidden behind the stopped flag.
  const showResultsView = view === 'results' && (result || (!stopped && (loading || Object.keys(partial).length > 0)))
  // Users & Activity Log / My Activity have no right-hand panel (no
  // scan/history context to summarize there), so they don't reserve the
  // panelWidth gutter the way dashboard/history/results do.
  const hasRightPanel = view === 'dashboard' || view === 'history' || showResultsView

  if (!authChecked) {
    return null
  }

  if (inviteToken && !authToken) {
    return <AcceptInviteView token={inviteToken} onAccepted={handleLoggedIn} />
  }

  if (!authToken) {
    return <AuthView onLoggedIn={handleLoggedIn} />
  }

  if (mustChangePassword) {
    return <ForcePasswordChangeView token={authToken} onChanged={() => setMustChangePassword(false)} />
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#0d0e11' }}>
      {/* Ambient scanline */}
      <div className="scanline-effect" />

      {docxReady && (
        <DocxReadyBanner
          indicator={docxReady.indicator}
          onDownload={handleDownloadReadyDocx}
          onDismiss={handleDismissDocxReady}
        />
      )}

      <Sidebar activeView={activeNav} onNavigate={handleNavigate} role={authRole}
               collapsed={sidebarCollapsed} onToggleCollapse={() => setSidebarCollapsed(c => {
                 const next = !c
                 localStorage.setItem('sidebarCollapsed', String(next))
                 return next
               })} />

      <div className="flex flex-col flex-1 min-w-0 min-h-0 overflow-hidden" style={{ marginLeft: sidebarCollapsed ? 64 : 240, marginRight: hasRightPanel ? panelWidth : 0 }}>
        {view !== 'pivot' && (
          <Header
            scanIndicator={view === 'results' ? scanIndicator : ''}
            threatActive={threatActive}
            authEmail={authEmail}
            onOpenAccount={() => setShowAccountPanel(true)}
          />
        )}

        <main className="flex-1 min-h-0 overflow-y-auto">
          {(view === 'dashboard' || (view === 'results' && !result && !loading && !Object.keys(partial).length)) && (
            <DashboardView
              history={history}
              onScan={handleScan}
              onRescan={handleRescan}
              onViewHistory={handleViewHistory}
              onViewPivot={handleViewPivot}
              onExportReport={handleExportReport}
              onExportEvidenceCsv={handleExportEvidenceCsv}
              onExportJson={handleExportJson}
              onExportDocx={handleExportDocx}
              loading={loading}
              error={error}
              searchInputRef={searchInputRef}
              onStop={handleStopScan}
            />
          )}

          {showResultsView && (
            <ResultsView
              result={result}
              partial={partial}
              scanIndicator={scanIndicator}
              loading={loading}
              error={error}
              onRescan={handleRescan}
              onViewPivot={() => handleNavigate('pivot')}
              onStop={handleStopScan}
              onExportReport={handleExportReport}
              onExportEvidenceCsv={handleExportEvidenceCsv}
              onExportJson={handleExportJson}
              onExportDocx={handleExportDocx}
              docxDisabled={aiSummaryLoading || !result?.ai_summary}
            />
          )}

          {view === 'history' && (
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-bold"
                    style={{ fontSize: 20, color: '#e3e2e6', fontFamily: 'Geist, sans-serif' }}>
                  Investigation Ledger
                </h2>
                <button
                  onClick={handleExportHistoryCsv}
                  disabled={history.length === 0}
                  className="transition-all active:scale-95 disabled:opacity-40 whitespace-nowrap"
                  style={{
                    background: 'transparent',
                    color: '#bbcabf',
                    border: '1px solid #3c4a42',
                    borderRadius: 2,
                    padding: '8px 16px',
                    fontSize: 12,
                    fontWeight: 600,
                    fontFamily: 'JetBrains Mono, monospace',
                    cursor: 'pointer',
                  }}>
                  EXPORT CSV
                </button>
              </div>
              <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
                <HistoryTable rows={ledgerRows} onViewHistory={handleViewHistory} onRescan={handleRescan} onViewPivot={handleViewPivot} onExportReport={handleExportReport} onExportEvidenceCsv={handleExportEvidenceCsv} onExportJson={handleExportJson} onExportDocx={handleExportDocx} onDeleteHistory={handleDeleteHistory} />
                {ledgerHasMore && (
                  <div style={{ textAlign: 'center', marginTop: 16 }}>
                    <button
                      onClick={handleLoadMoreHistory}
                      disabled={ledgerLoading}
                      style={{
                        background: 'transparent',
                        color: '#bbcabf',
                        border: '1px solid #3c4a42',
                        borderRadius: 2,
                        padding: '8px 20px',
                        fontSize: 12,
                        fontWeight: 600,
                        fontFamily: 'JetBrains Mono, monospace',
                        cursor: 'pointer',
                      }}
                    >
                      {ledgerLoading ? 'LOADING...' : 'LOAD MORE'}
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {view === 'users' && authRole === 'Admin' && (
            <UsersView token={authToken} currentUserId={authUserId} />
          )}

          {view === 'myActivity' && authRole === 'Analyst' && (
            <MyActivityView token={authToken} email={authEmail} name={authName} role={authRole} />
          )}
        </main>
      </div>

      {hasRightPanel && (
        <div
          onMouseDown={startPanelResize}
          style={{
            position: 'fixed',
            top: 0,
            bottom: 0,
            right: panelWidth,
            width: 6,
            cursor: 'ew-resize',
            zIndex: 15,
            background: 'transparent',
          }}
        />
      )}

      {view === 'dashboard' && <RightPanel history={history} verdictCounts={verdictCounts} width={panelWidth} />}

      {showResultsView && (
        <AiSummaryPanel
          scanInProgress={!stopped && (loading || (!result && Object.keys(partial).length > 0))}
          loading={aiSummaryLoading}
          summary={aiSummary}
          error={aiSummaryError}
          width={panelWidth}
          onRegenerate={handleRegenerateAiSummary}
          onStop={handleStopAiSummary}
        />
      )}

      {view === 'history' && <RightPanel history={history} verdictCounts={verdictCounts} width={panelWidth} />}

      {view === 'pivot' && (
        <div style={{ position: 'fixed', left: sidebarCollapsed ? 64 : 240, top: 0, right: 0, bottom: 0, zIndex: 20 }}>
          <PivotVisualization defaultIndicator={pivotIndicator} apiKey={apiKey} onScan={handleScan} onRescan={handleRescan} />
        </div>
      )}

      {showAccountPanel && (
        <AccountPanel
          token={authToken}
          onClose={() => setShowAccountPanel(false)}
          onLogout={() => { setShowAccountPanel(false); handleLogout() }}
          onAccountDeleted={() => { setShowAccountPanel(false); handleLogout() }}
        />
      )}
    </div>
  )
}