import { VERDICT_COLOR } from './verdictColors'

export const VERDICT_STYLES = {
  high:        { bg: '#1f1f23', border: VERDICT_COLOR.high,        text: VERDICT_COLOR.high,        pill: '#93000a' },
  medium_risk: { bg: '#1f1f23', border: VERDICT_COLOR.medium_risk, text: VERDICT_COLOR.medium_risk, pill: '#c2410c' },
  low_risk:    { bg: '#1f1f23', border: VERDICT_COLOR.low_risk,    text: VERDICT_COLOR.low_risk,    pill: '#a16207' },
  suspicious:  { bg: '#1f1f23', border: VERDICT_COLOR.suspicious,  text: VERDICT_COLOR.suspicious,  pill: '#b45309' },
  clean:       { bg: '#1f1f23', border: VERDICT_COLOR.clean,       text: VERDICT_COLOR.clean,       pill: '#10b981' },
  no_data:     { bg: '#1b1b1f', border: VERDICT_COLOR.no_data,     text: '#86948a',                 pill: VERDICT_COLOR.no_data },
}

export const VERDICT_LABEL = {
  high:        'High Risk',
  medium_risk: 'Medium Risk',
  low_risk:    'Low Risk',
  suspicious:  'Suspicious',
  clean:       'Clean',
  no_data:     'No Data',
}

export function getStyle(verdict) {
  return VERDICT_STYLES[verdict] || VERDICT_STYLES.no_data
}

export function VerdictPill({ verdict }) {
  const s = getStyle(verdict)
  return (
    <span style={{
      background: `${s.text}22`,
      color: s.text,
      border: `1px solid ${s.text}44`,
      padding: '2px 8px',
      borderRadius: 2,
      fontSize: 10,
      fontWeight: 700,
      fontFamily: 'JetBrains Mono, monospace',
      letterSpacing: '0.07em',
      textTransform: 'uppercase',
      whiteSpace: 'nowrap',
    }}>
      {VERDICT_LABEL[verdict] || verdict}
    </span>
  )
}
