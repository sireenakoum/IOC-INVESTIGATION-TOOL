import { getStyle, VERDICT_LABEL } from '../utils/verdict'
import { guessIndicatorType } from '../utils/indicatorType'
import { VERDICT_COLOR as RING_COLOR, VERDICT_COLOR_RGB } from '../utils/verdictColors'
import ExportMenu from './ExportMenu'

const ACTION_LABEL = {
  high:        'QUARANTINE IMMEDIATELY',
  medium_risk: 'INVESTIGATE FURTHER',
  low_risk:    'MONITOR CLOSELY',
  suspicious:  'REVIEW ACTIVITY',
  clean:       'NO ACTION REQUIRED',
  no_data:     'INSUFFICIENT DATA',
}

function ScoreRing({ score, verdict }) {
  const color   = RING_COLOR[verdict] || '#3c4a42'
  const isHigh  = verdict === 'high'
  return (
    <div className="w-20 h-20 rounded-full flex items-center justify-center relative overflow-hidden shrink-0"
         style={{ border: `4px solid ${color}`,
                  background: `${color}1a`,
                  ...(isHigh ? {} : {}) }}>
      {isHigh && <div className="absolute inset-0 pulse-danger" style={{ background: `${color}0d` }} />}
      <span className="relative z-10 font-bold tabular-nums" style={{ fontSize: 28, color, fontFamily: 'Geist, sans-serif' }}>
        {score}
      </span>
    </div>
  )
}

export default function VerdictCard({ result, inline, onExportReport, onExportEvidenceCsv, onExportJson, onExportDocx, docxDisabled }) {
  const s         = getStyle(result.verdict)
  const ringColor = RING_COLOR[result.verdict] || '#3c4a42'
  const triggered = (result.triggered_by || []).join(', ')
  const isHigh    = result.verdict === 'high'

  return (
    <div className="relative rounded p-6 flex items-center justify-between gap-6"
         style={{ background: '#1f1f23', border: `1px solid ${ringColor}33` }}>

      {/* Background glow for high risk (clipped to card's rounded corners without clipping the card itself) */}
      {isHigh && (
        <div className="absolute inset-0 rounded overflow-hidden pointer-events-none">
          <div className="absolute inset-0 pointer-events-none"
               style={{ background: `radial-gradient(ellipse at left center, rgba(${VERDICT_COLOR_RGB.high},0.05) 0%, transparent 60%)` }} />
        </div>
      )}

      <div className="relative z-10 flex items-center gap-6">
        <ScoreRing score={result.score} verdict={result.verdict} />
        <div>
          <div className="flex items-center gap-2 mb-1">
            <p className="uppercase"
               style={{ fontSize: 10, color: '#bbcabf', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono, monospace' }}>
            </p>
            <span className="uppercase rounded" style={{ fontSize: 10, padding: '2px 10px', color: '#bbcabf',
                                                           border: '1px solid #3c4a42', letterSpacing: '0.08em',
                                                           fontFamily: 'JetBrains Mono, monospace' }}>
              {guessIndicatorType(result.indicator)}
            </span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-bold" style={{ fontSize: 28, color: ringColor, fontFamily: 'Geist, sans-serif' }}>
              {VERDICT_LABEL[result.verdict] || result.verdict}
            </span>
            <span style={{ fontSize: 12, color: '#bbcabf', fontFamily: 'JetBrains Mono, monospace' }}>
              / 20 signals
            </span>
          </div>
          {triggered && (
            <p className="mt-1 text-xs" style={{ color: '#bbcabf', fontFamily: 'Geist, sans-serif' }}>
              Triggered by {triggered}
            </p>
          )}
          <div className="flex gap-5 mt-3 pt-3 text-xs" style={{ borderTop: '1px solid rgba(60,74,66,0.5)' }}>
            <span style={{ color: '#bbcabf' }}>
              Action&nbsp;
              <span className="font-medium" style={{ color: '#e3e2e6' }}>{result.recommendation}</span>
            </span>
            <span style={{ color: '#bbcabf' }}>
              Consensus&nbsp;
              <span className="font-medium" style={{ color: '#e3e2e6' }}>{result.consensus_ratio}</span>
            </span>
          </div>
        </div>
      </div>

      {/* Action button */}
      <div className="relative z-10 shrink-0 flex items-center gap-2">
        <ExportMenu
          indicator={result.indicator}
          onExportReport={onExportReport}
          onExportCsv={onExportEvidenceCsv}
          onExportJson={onExportJson}
          onExportDocx={onExportDocx}
          docxDisabled={docxDisabled}
          color={ringColor}
        />
        <button
          className="px-5 py-2.5 uppercase tracking-widest transition-all active:scale-95"
          style={{
            background: isHigh ? ringColor : 'transparent',
            color: isHigh ? '#690005' : ringColor,
            border: `1px solid ${ringColor}`,
            borderRadius: 2,
            fontSize: 10,
            fontWeight: 700,
            fontFamily: 'JetBrains Mono, monospace',
            letterSpacing: '0.08em',
            ...(isHigh ? { boxShadow: `0 0 20px ${ringColor}40` } : {}),
          }}>
          {ACTION_LABEL[result.verdict] || 'REVIEW'}
        </button>
      </div>
    </div>
  )
}