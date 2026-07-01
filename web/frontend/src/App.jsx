import { useState, useEffect, useRef } from 'react'
import { fetchScanStream, fetchClear, fetchResult, fetchHistory } from './api/scan'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import DashboardView from './components/DashboardView'
import ResultsView from './components/ResultsView'
import RightPanel from './components/RightPanel'
import HistoryTable from './components/HistoryTable'

export default function App() {
  const [result,        setResult]        = useState(null)
  const [partial,       setPartial]       = useState({})
  const [scanIndicator, setScanIndicator] = useState('')
  const [history,       setHistory]       = useState([])
  const [loading,       setLoading]       = useState(false)
  const [error,         setError]         = useState('')
  const [view,          setView]          = useState('dashboard')
  const searchInputRef = useRef(null)

  useEffect(() => {
    fetchHistory().then(setHistory).catch(() => {})
  }, [])

  async function handleScan(indicator) {
    setLoading(true)
    setError('')
    setResult(null)
    setPartial({})
    setScanIndicator(indicator)
    setView('results')

    await fetchScanStream(
      indicator,
      (key, data) => setPartial(prev => ({ ...prev, [key]: data })),
      (data) => {
        setResult(data)
        setPartial({})
        setLoading(false)
        fetchHistory().then(setHistory).catch(() => {})
      },
      (msg) => {
        setError(msg)
        setLoading(false)
      },
    )
  }

  async function handleRescan(indicator) {
    setLoading(true)
    setError('')
    setResult(null)
    setPartial({})
    setScanIndicator(indicator)
    setView('results')

    try {
      await fetchClear(indicator)
    } catch (e) {
      setError(e.message)
      setLoading(false)
      return
    }

    await fetchScanStream(
      indicator,
      (key, data) => setPartial(prev => ({ ...prev, [key]: data })),
      (data) => {
        setResult(data)
        setPartial({})
        fetchHistory().then(setHistory).catch(() => {})
        setLoading(false)
      },
      (msg) => {
        setError(msg)
        setLoading(false)
      },
    )
  }

  async function handleViewHistory(indicator) {
    setLoading(true)
    setError('')
    setResult(null)
    setPartial({})
    setScanIndicator(indicator)
    setView('results')
    try {
      const data = await fetchResult(indicator)
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  function handleNavigate(id) {
    if (id === 'scan') {
      setView('dashboard')
      setTimeout(() => searchInputRef.current?.focus(), 50)
    } else if (id === 'history') {
      setView('history')
    } else if (id === 'dashboard') {
      setResult(null)
      setView('dashboard')
    }
  }

  const activeNav   = view === 'results' ? 'scan' : view
  const threatActive = result && ['high', 'medium_risk'].includes(result.verdict)

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#0d0e11' }}>
      {/* Ambient scanline */}
      <div className="scanline-effect" />

      <Sidebar activeView={activeNav} onNavigate={handleNavigate} />

      <div className="flex flex-col flex-1 min-w-0 min-h-0 overflow-hidden" style={{ marginLeft: 280, marginRight: 300 }}>
        <Header
          scanIndicator={view === 'results' ? scanIndicator : ''}
          threatActive={threatActive}
        />

        <main className="flex-1 min-h-0 overflow-y-auto">
          {(view === 'dashboard' || (view === 'results' && !result && !loading)) && (
            <DashboardView
              history={history}
              onScan={handleScan}
              onRescan={handleRescan}
              onViewHistory={handleViewHistory}
              loading={loading}
              error={error}
              searchInputRef={searchInputRef}
            />
          )}

          {view === 'results' && (result || loading) && (
            <ResultsView
              result={result}
              partial={partial}
              scanIndicator={scanIndicator}
              loading={loading}
              error={error}
              onScan={handleScan}
              onRescan={handleRescan}
            />
          )}

          {view === 'history' && (
            <div className="p-6">
              <h2 className="font-bold mb-4"
                  style={{ fontSize: 20, color: '#e3e2e6', fontFamily: 'Geist, sans-serif' }}>
                Investigation Ledger
              </h2>
              <div className="rounded p-5" style={{ background: '#1f1f23', border: '1px solid #3c4a42' }}>
                <HistoryTable rows={history} onViewHistory={handleViewHistory} onRescan={handleRescan} />
              </div>
            </div>
          )}
        </main>
      </div>

      <RightPanel history={history} />
    </div>
  )
}
