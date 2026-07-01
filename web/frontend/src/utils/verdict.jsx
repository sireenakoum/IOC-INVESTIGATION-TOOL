export const VERDICT_STYLES = {
  high:        { bg: '#1f1f23', border: '#ffb4ab', text: '#ffb4ab', pill: '#93000a' },
  medium_risk: { bg: '#1f1f23', border: '#f97316', text: '#f97316', pill: '#c2410c' },
  low_risk:    { bg: '#1f1f23', border: '#eab308', text: '#eab308', pill: '#a16207' },
  suspicious:  { bg: '#1f1f23', border: '#f59e0b', text: '#f59e0b', pill: '#b45309' },
  clean:       { bg: '#1f1f23', border: '#4edea3', text: '#4edea3', pill: '#10b981' },
  no_data:     { bg: '#1b1b1f', border: '#3c4a42', text: '#86948a', pill: '#3c4a42' },
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
