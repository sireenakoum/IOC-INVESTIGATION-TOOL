import { useState, useEffect, useRef } from 'react'
import * as d3 from 'd3'
import { fetchResult, fetchPivotStatus } from '../api/scan'
import { guessIndicatorType } from '../utils/indicatorType'
import { VERDICT_COLOR } from '../utils/verdictColors'

const DETAIL_COLOR = '#4cd7f6'

function truncate(s, n = 22) {
  if (!s) return s
  return s.length > n ? s.slice(0, n) + '…' : s
}

function mergePivotStatuses(pivot, statuses) {
  // Overlays a fresh DB-only status check onto the pivot snapshot that was
  // stored at the time the parent indicator was pivot-scanned. IOCs that
  // have since been scanned directly (by this user) flip to "full scan"
  // with their current verdict/score/timestamp; nothing here re-triggers
  // a scan of anything — statuses come entirely from /api/pivot/status.
  const fullScan = { ...(pivot.pivot_from_full_scan || {}) }
  const verdicts = { ...(pivot.pivot_verdicts || {}) }
  const scores   = { ...(pivot.pivot_scores || {}) }

  Object.entries(statuses || {}).forEach(([ioc, status]) => {
    if (status.scanned) {
      fullScan[ioc] = status.timestamp
      verdicts[ioc] = status.verdict
      scores[ioc]   = status.score
    } else {
      delete fullScan[ioc]
    }
  })

  return { ...pivot, pivot_from_full_scan: fullScan, pivot_verdicts: verdicts, pivot_scores: scores }
}

function buildGraph(result) {
  const pivot      = result.pivot || {}
  const sourcesMap = pivot.sources_map || {}
  const pivotIocs  = pivot.pivot_iocs || []
  const pivotExtras = pivot.pivot_extras || {}

  const nodes = [{
    id: result.indicator,
    type: 'root',
    verdict: result.verdict,
    score: result.score,
  }]
  const links = []

  const fullScanPivots = pivot.pivot_from_full_scan || {}

  pivotIocs.forEach(ioc => {
    if (ioc === result.indicator) return
    nodes.push({
      id: ioc,
      type: 'scanned',
      verdict: pivot.pivot_verdicts?.[ioc],
      score: pivot.pivot_scores?.[ioc],
      sources: sourcesMap[ioc] || [],
      whois: pivot.pivot_whois?.[ioc] || null,
      fromFullScan: Object.prototype.hasOwnProperty.call(fullScanPivots, ioc),
      fullScanTimestamp: fullScanPivots[ioc] || null,
    })
    links.push({ source: result.indicator, target: ioc, relation: (pivot.relation_map?.[ioc] || []).join(', ') })
  })

  Object.keys(pivotExtras).forEach(ioc => {
    if (ioc === result.indicator) return
    const extra = pivotExtras[ioc]
    nodes.push({
      id: ioc,
      type: 'detail',
      bucketType: extra.type,
      sources: extra.sources || [],
      details: extra.details || {},
    })
    links.push({ source: result.indicator, target: ioc, relation: (extra.relation || []).join(', ') })
  })

  return { nodes, links }
}

function nodeColor(node) {
  if (node.type === 'detail') return DETAIL_COLOR
  return VERDICT_COLOR[node.verdict] || VERDICT_COLOR.no_data
}

function GraphNode({ node, simulation, onSelect }) {
  const groupRef = useRef(null)
  const isRoot   = node.type === 'root'
  const radius   = isRoot ? 34 : 22
  const color    = nodeColor(node)

  useEffect(() => {
    if (!groupRef.current || !simulation) return
    const drag = d3.drag()
      .on('start', (event) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        node.fx = node.x
        node.fy = node.y
      })
      .on('drag', (event) => {
        node.fx = event.x
        node.fy = event.y
      })
      .on('end', (event) => {
        if (!event.active) simulation.alphaTarget(0)
        node.fx = null
        node.fy = null
      })
    d3.select(groupRef.current).call(drag)
  }, [simulation, node])

  return (
    <g
      ref={groupRef}
      transform={`translate(${node.x || 0}, ${node.y || 0})`}
      style={{ cursor: 'pointer' }}
      onClick={(e) => { e.stopPropagation(); onSelect(node) }}
    >
      <circle r={radius} fill="#1b1b1f" stroke={color} strokeWidth={isRoot ? 2.5 : 1.5}
              strokeDasharray={node.fromFullScan ? '4 2' : undefined} />
      <text textAnchor="middle" dy={4} fill="#e3e2e6" fontSize={isRoot ? 11 : 10}
            fontFamily="JetBrains Mono, monospace">
        {truncate(node.id, isRoot ? 20 : 16)}
      </text>
      <text textAnchor="middle" dy={radius + 14} fill={color} fontSize={9}
            fontFamily="JetBrains Mono, monospace">
        {node.type === 'detail' ? node.bucketType : node.fromFullScan ? `${node.verdict || 'no verdict'} (full scan)` : (node.verdict || 'no verdict')}
      </text>
    </g>
  )
}

function ForceGraph({ result, onSelectNode }) {
  const containerRef  = useRef(null)
  const svgRef        = useRef(null)
  const simulationRef = useRef(null)
  const linksRef      = useRef([])
  const [dims, setDims]           = useState({ width: 800, height: 600 })
  const [nodes, setNodes]         = useState([])
  const [, forceLinkRender]       = useState(0)
  const [transform, setTransform] = useState(d3.zoomIdentity)

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const update = () => setDims({ width: el.clientWidth, height: el.clientHeight })
    update()
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    const { nodes: graphNodes, links: graphLinks } = buildGraph(result)
    linksRef.current = graphLinks
    setNodes(graphNodes)

    const simulation = d3.forceSimulation(graphNodes)
      .force('link', d3.forceLink(graphLinks).id(d => d.id).distance(220))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(dims.width / 2, dims.height / 2))
      .force('collide', d3.forceCollide(60))
      .on('tick', () => {
        setNodes([...graphNodes])
        forceLinkRender(t => t + 1)
      })

    simulationRef.current = simulation
    return () => simulation.stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result])

  useEffect(() => {
    const simulation = simulationRef.current
    if (!simulation) return
    simulation.force('center', d3.forceCenter(dims.width / 2, dims.height / 2))
    simulation.alpha(0.3).restart()
  }, [dims])

  useEffect(() => {
    const svgEl = svgRef.current
    if (!svgEl) return
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => setTransform(event.transform))
    d3.select(svgEl).call(zoom)
    return () => d3.select(svgEl).on('.zoom', null)
  }, [])

  const links = linksRef.current

  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%', background: '#161619' }}>
      <svg ref={svgRef} width="100%" height="100%" style={{ display: 'block' }}
           onClick={() => onSelectNode(null)}>
        <g transform={transform.toString()}>
          {links.map((l, i) => {
            const source = typeof l.source === 'object' ? l.source : nodes.find(n => n.id === l.source)
            const target = typeof l.target === 'object' ? l.target : nodes.find(n => n.id === l.target)
            if (!source || !target) return null
            const midX = (source.x + target.x) / 2
            const midY = (source.y + target.y) / 2
            return (
              <g key={i}>
                <line x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                      stroke="#3c4a42" strokeWidth={1.5} />
                {l.relation && (
                  <text x={midX} y={midY} textAnchor="middle" dy={-4}
                        fill="#86948a" fontSize={9} fontFamily="JetBrains Mono, monospace"
                        style={{ pointerEvents: 'none' }}>
                    {truncate(l.relation, 40)}
                  </text>
                )}
              </g>
            )
          })}
          {nodes.map(node => (
            <GraphNode key={node.id} node={node} simulation={simulationRef.current} onSelect={onSelectNode} />
          ))}
        </g>
      </svg>
    </div>
  )
}

function DetailsPanel({ node, result, onClose, onScan, onRescan }) {
  if (!node) return null

  const isRoot       = node.type === 'root'
  const isDetail     = node.type === 'detail'
  const typeLabel    = guessIndicatorType(node.id)
  const color        = nodeColor(node)
  const log          = !isRoot && !isDetail
    ? (result.pivot?.pivot_log_by_ioc?.[node.id] || '(no log captured)')
    : null

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 380,
      background: '#1b1b1f', borderLeft: '1px solid #3c4a42',
      padding: 20, overflowY: 'auto', zIndex: 50,
      boxShadow: '-8px 0 24px rgba(0,0,0,0.4)',
    }}>
      <div className="flex items-center justify-between" style={{ marginBottom: 16 }}>
        <p style={{ fontSize: 10, fontWeight: 700, color: '#bbcabf', textTransform: 'uppercase',
                    letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace', margin: 0 }}>
          {isRoot ? 'Root Indicator' : isDetail ? 'Additional Candidate' : node.fromFullScan ? 'Full Scan (from history)' : 'Pivot Scan'}
        </p>
        <button onClick={onClose} style={{
          background: 'transparent', border: 'none', color: '#86948a', cursor: 'pointer', fontSize: 16,
        }}>
          ✕
        </button>
      </div>

      <p style={{ fontSize: 13, color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace',
                  wordBreak: 'break-word', margin: '0 0 4px' }}>
        {node.id}
      </p>
      <p style={{ fontSize: 11, color: '#86948a', margin: '0 0 8px' }}>{typeLabel}</p>

      {!isRoot && !isDetail && (
        <span style={{
          background: node.fromFullScan ? '#4cd7f622' : '#4edea322',
          color: node.fromFullScan ? '#4cd7f6' : '#4edea3',
          fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 2,
          fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.05em',
          display: 'inline-block', marginBottom: 16,
        }}>
          {node.fromFullScan
            ? `FROM HISTORY · LAST SCANNED ${node.fullScanTimestamp ? node.fullScanTimestamp.slice(0, 10) : 'UNKNOWN'}`
            : 'PIVOT SCAN COMPLETE'}
        </span>
      )}

      {isDetail && (
        <>
          <p style={{ fontSize: 10, color: '#86948a', margin: '0 0 2px' }}>TYPE</p>
          <p style={{ fontSize: 13, color, fontFamily: 'JetBrains Mono, monospace', margin: '0 0 12px' }}>
            {node.bucketType || 'unknown'}
          </p>
          <p style={{ fontSize: 12, color: '#86948a', margin: '0 0 16px' }}>
            via {(node.sources || []).join(', ') || 'unknown source'}
          </p>
          {Object.keys(node.details || {}).length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {Object.entries(node.details).map(([key, value]) => (
                <div key={key} className="flex justify-between" style={{ fontSize: 12 }}>
                  <span style={{ color: '#86948a', textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: 10 }}>
                    {key.replace(/_/g, ' ')}
                  </span>
                  <span style={{ color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace' }}>
                    {String(value ?? '—')}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ fontSize: 12, color: '#86948a' }}>No additional details available.</p>
          )}

          <p style={{ fontSize: 12, color: '#86948a', margin: '16px 0 12px' }}>
            This indicator hasn't been scanned yet.
          </p>
          <button
            onClick={() => onScan(node.id)}
            style={{
              width: '100%', padding: 10, background: '#4edea3', border: 'none',
              color: '#003824', borderRadius: 2, fontWeight: 700, cursor: 'pointer',
              fontSize: 12, fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            SCAN THIS INDICATOR
          </button>
        </>
      )}

      {!isDetail && (
        <>
          <div className="flex gap-6" style={{ marginBottom: 12 }}>
            <div>
              <p style={{ fontSize: 10, color: '#86948a', margin: '0 0 2px' }}>VERDICT</p>
              <p style={{ fontSize: 13, color, fontFamily: 'JetBrains Mono, monospace', margin: 0 }}>
                {node.verdict || 'no verdict'}
              </p>
            </div>
            <div>
              <p style={{ fontSize: 10, color: '#86948a', margin: '0 0 2px' }}>SCORE</p>
              <p style={{ fontSize: 13, color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace', margin: 0 }}>
                {node.score ?? '—'}
              </p>
            </div>
          </div>

          {node.whois && !node.whois.error && (
            <div style={{ marginBottom: 16 }}>
              <p style={{ fontSize: 10, color: '#86948a', textTransform: 'uppercase',
                          letterSpacing: '0.05em', margin: '0 0 8px' }}>NETWORK INFO</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {Object.entries(node.whois).map(([key, value]) => (
                  <div key={key} className="flex justify-between" style={{ fontSize: 12 }}>
                    <span style={{ color: '#86948a', textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: 10 }}>
                      {key.replace(/_/g, ' ')}
                    </span>
                    <span style={{ color: '#e3e2e6', fontFamily: 'JetBrains Mono, monospace' }}>
                      {String(value ?? '—')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {isRoot && result.recommendation && (
            <p style={{ fontSize: 12, color: '#bbcabf', margin: '0 0 16px' }}>
              {result.recommendation}
            </p>
          )}

          {!isRoot && node.fromFullScan && (
            <>
              <p style={{ fontSize: 12, color: '#86948a', margin: '0 0 12px' }}>
                This is a stored result from a full scan run earlier — not a pivot
                scan that just ran. Rescan to get current data.
              </p>
              <button
                onClick={() => onRescan(node.id)}
                style={{
                  width: '100%', padding: 10, background: 'transparent',
                  border: '1px solid #4cd7f6', color: '#4cd7f6', borderRadius: 2,
                  fontWeight: 700, cursor: 'pointer', fontSize: 12,
                  fontFamily: 'JetBrains Mono, monospace', marginBottom: 16,
                }}
              >
                RESCAN THIS INDICATOR
              </button>
            </>
          )}

          {!isRoot && !node.fromFullScan && (
            <p style={{ fontSize: 12, color: '#86948a', margin: '0 0 16px' }}>
              via {(node.sources || []).join(', ') || 'unknown source'}
            </p>
          )}

          {log && (
            <details style={{ border: '1px solid #3c4a42', borderRadius: 2 }}>
              <summary style={{ padding: '8px 12px', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace',
                                 fontSize: 11, color: '#bbcabf' }}>
                {node.fromFullScan ? 'Full scan details' : 'Scan log'}
              </summary>
              <pre style={{ margin: 0, padding: '10px 12px', borderTop: '1px solid #3c4a42',
                             fontSize: 10, color: '#86948a', fontFamily: 'JetBrains Mono, monospace',
                             whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {log}
              </pre>
            </details>
          )}
        </>
      )}
    </div>
  )
}

export default function PivotTreeView({ defaultIndicator, apiKey, onScan, onRescan }) {
  const [query,        setQuery]        = useState(defaultIndicator || '')
  const [result,       setResult]       = useState(null)
  const [loading,      setLoading]      = useState(false)
  const [error,        setError]        = useState('')
  const [selectedNode, setSelectedNode] = useState(null)

  const loadIndicatorRef = useRef()

  useEffect(() => {
    if (!defaultIndicator) return
    setQuery(defaultIndicator)
  }, [defaultIndicator])

  useEffect(() => {
    loadIndicatorRef.current = true
    if (defaultIndicator && apiKey) {
      loadIndicator(defaultIndicator)
    }
    return () => { loadIndicatorRef.current = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaultIndicator, apiKey])

  async function loadIndicator(indicator) {
    setLoading(true)
    setError('')
    setSelectedNode(null)
    try {
      const data = await fetchResult(apiKey, indicator)
      if (!loadIndicatorRef.current) return
      const pivotIocs = data.pivot?.pivot_iocs || []
      if (pivotIocs.length) {
        try {
          const { statuses } = await fetchPivotStatus(apiKey, indicator)
          if (!loadIndicatorRef.current) return
          data.pivot = mergePivotStatuses(data.pivot, statuses)
        } catch {
          // Non-fatal — if the live status check fails, still show the
          // stored pivot map as-is rather than blocking the whole load.
        }
      }
      if (loadIndicatorRef.current) setResult(data)
    } catch (e) {
      if (loadIndicatorRef.current) setError(e.message)
      if (loadIndicatorRef.current) setResult(null)
    } finally {
      if (loadIndicatorRef.current) setLoading(false)
    }
  }

  function handleSubmit() {
    const q = query.trim()
    if (!q) return
    if (!apiKey) { setError('API key not available yet. Please wait.'); return }
    loadIndicator(q)
  }

  const hasPivotData = result && Object.keys(result.pivot?.sources_map || {}).length > 0

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', background: '#161619', overflow: 'hidden' }}>
      <div style={{
        position: 'absolute', top: 16, left: 16, zIndex: 40,
        display: 'flex', gap: 10, background: 'rgba(31,31,35,0.85)', backdropFilter: 'blur(8px)',
        border: '1px solid #3c4a42', borderRadius: 4, padding: 12,
      }}>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSubmit()}
          type="text"
          placeholder="Enter an indicator to view its pivot map…"
          className="focus:outline-none"
          style={{
            background: '#1b1b1f', border: '1px solid #3c4a42', borderRadius: 2,
            padding: '9px 12px', fontSize: 13, color: '#e3e2e6', width: 320,
            fontFamily: 'JetBrains Mono, monospace',
          }}
        />
        <button
          onClick={handleSubmit}
          disabled={loading || !query.trim()}
          style={{
            background: '#4edea3', color: '#003824', border: 'none', borderRadius: 2,
            padding: '9px 18px', fontSize: 12, fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace', cursor: 'pointer',
          }}>
          {loading ? 'LOADING…' : 'LOAD'}
        </button>
      </div>

      {error && (
        <p style={{ position: 'absolute', top: 70, left: 16, zIndex: 40, fontSize: 12, color: '#ffb4ab' }}>
          {error}
        </p>
      )}

      {!result && !loading && !error && (
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <p style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
            Enter an indicator above to view its pivot map.
          </p>
        </div>
      )}

      {result && !hasPivotData && (
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <p style={{ fontSize: 13, color: '#86948a', fontFamily: 'Geist, sans-serif' }}>
            No pivot IOCs found for this indicator.
          </p>
        </div>
      )}

      {hasPivotData && <ForceGraph result={result} onSelectNode={setSelectedNode} />}

      <DetailsPanel node={selectedNode} result={result} onClose={() => setSelectedNode(null)} onScan={onScan} onRescan={onRescan} />
    </div>
  )
}