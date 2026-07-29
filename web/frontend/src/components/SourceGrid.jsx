import { FINDINGS_COLOR } from '../utils/verdictColors'

const STREAM_KEYS = [
  ['vt',           'VirusTotal'],
  ['otx',          'OTX'],
  ['abuse',        'AbuseIPDB'],
  ['shodan',       'Shodan'],
  ['censys',       'Censys'],
  ['whois',        'WHOIS'],
  ['greynoise',    'GreyNoise'],
  ['urlhaus',      'URLhaus'],
  ['threatfox',    'ThreatFox'],
  ['urlscan',      'URLScan'],
  ['hybrid',       'Hybrid Analysis'],
  ['google_intel', 'Google Intel'],
]

const SHORT_LABELS = {
  'VirusTotal':      'VirusTotal',
  'OTX':             'OTX',
  'AbuseIPDB':       'AbuseIPDB',
  'Shodan':          'Shodan',
  'Censys':          'Censys',
  'WHOIS':           'WHOIS',
  'GreyNoise':       'GreyNoise',
  'URLhaus':         'URLhaus',
  'ThreatFox':       'ThreatFox',
  'URLScan':         'URLScan',
  'Hybrid Analysis': 'Hybrid Analysis',
  'Google Intel':    'Google Intel',
}

const VERDICT_ICON = {
  high:        'dangerous',
  medium_risk: 'warning',
  low_risk:    'info',
  suspicious:  'bug_report',
  clean:       'check_circle',
  no_data:     'help',
}

const LABEL_STYLE = {
  fontSize: 10, fontWeight: 700, color: '#bbcabf',
  letterSpacing: '0.07em', fontFamily: 'JetBrains Mono, monospace',
  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
  margin: '0 0 4px',
}

export default function SourceGrid({ perSource, partial = {}, loading = false }) {
  if (loading) {
    return (
      <div className="grid grid-cols-4 gap-2.5">
        {STREAM_KEYS.map(([key, label]) => {
          const done = key in partial
          if (done) {
            return (
              <div key={key} style={{
                background: '#0d1f17', border: '1px solid #4edea3',
                borderRadius: 4, padding: '10px 12px', minHeight: 80, overflow: 'hidden',
              }}>
                <p style={{ ...LABEL_STYLE, color: '#bbcabf' }}>
                  {SHORT_LABELS[label] || label}
                </p>
                <div className="flex items-center gap-1.5">
                  <span className="material-symbols-outlined" style={{ fontSize: 14, color: '#4edea3' }}>check_circle</span>
                  <span style={{ fontSize: 11, color: '#4edea3', fontFamily: 'JetBrains Mono, monospace' }}>Done</span>
                </div>
              </div>
            )
          }
          return (
            <div key={key} className="relative overflow-hidden" style={{
              background: '#1f1f23', border: '1px solid #3c4a42',
              borderRadius: 4, minHeight: 80,
            }}>
              <div className="skeleton-shimmer absolute inset-0" />
              <p className="absolute top-3 left-3" style={{ ...LABEL_STYLE, color: '#3c4a42' }}>
                {SHORT_LABELS[label] || label}
              </p>
              <span className="material-symbols-outlined absolute top-3 right-3 animate-spin"
                    style={{ fontSize: 14, color: '#3c4a42' }}>
                refresh
              </span>
            </div>
          )
        })}
      </div>
    )
  }

  if (!perSource) return null

  return (
    <div className="grid grid-cols-4 gap-2.5">
      {Object.entries(perSource).map(([name, src]) => {
        const findingsColor = FINDINGS_COLOR[src.findings_tier] || FINDINGS_COLOR.none
        const count = src.has_data
          ? (src.evidence_count > 0
              ? `${src.evidence_count} finding${src.evidence_count !== 1 ? 's' : ''}`
              : 'Checked')
          : 'No data'

        if (!src.has_data) {
          return (
            <div key={name} style={{
              background: '#1b1b1f', border: '1px solid #292a2d',
              borderRadius: 4, padding: '10px 12px', minHeight: 80, overflow: 'hidden',
            }}>
              <p style={{ ...LABEL_STYLE, color: '#3c4a42' }}>
                {SHORT_LABELS[name] || name}
              </p>
              <p style={{ fontSize: 12, fontWeight: 700, color: '#3c4a42',
                fontFamily: 'JetBrains Mono, monospace', margin: '0 0 2px' }}>—</p>
              <p style={{ fontSize: 11, color: '#3c4a42', fontFamily: 'Geist, sans-serif', margin: 0 }}>
                No data
              </p>
            </div>
          )
        }

        return (
          <div key={name} className="transition-colors hover:brightness-110" style={{
            background: '#1b1b1f', border: `1px solid ${findingsColor}33`,
            borderRadius: 4, padding: '10px 12px', minHeight: 80, overflow: 'hidden',
          }}>
            <p style={{ ...LABEL_STYLE, color: '#bbcabf' }}>
              {SHORT_LABELS[name] || name}
            </p>
            <p style={{
              fontSize: 12, fontWeight: 700, color: findingsColor,
              fontFamily: 'Geist, sans-serif',
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              margin: '0 0 2px',
            }}>
              {src.findings_label}
            </p>
            <p style={{
              fontSize: 11, color: '#86948a',
              fontFamily: 'Geist, sans-serif',
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              margin: 0,
            }}>
              {count}
            </p>
          </div>
        )
      })}
    </div>
  )
}
