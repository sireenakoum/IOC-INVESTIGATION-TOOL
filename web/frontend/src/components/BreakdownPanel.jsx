function dotColor(line) {
  const t = line.trim()
  if (t.includes('→ +') && !t.includes('→ +0')) return '#4edea3'
  if (t.includes('→ -'))  return '#ffb4ab'
  if (t.startsWith('──')) return null  // section header
  return '#86948a'
}

function parseScore(line) {
  const match = line.match(/→ ([+-]\d+)/)
  return match ? match[1] : null
}

function isHeader(line) {
  return line.trim().startsWith('──')
}

function headerLabel(line) {
  return line.trim().replace(/^──\s*/, '').replace(/\s*──$/, '').trim()
}

export default function BreakdownPanel({ breakdown }) {
  if (!breakdown?.length) return null

  // Split into sections by header lines
  const sections = []
  let current = null

  for (const line of breakdown) {
    if (isHeader(line)) {
      if (current) sections.push(current)
      current = { title: headerLabel(line), rows: [] }
    } else if (current) {
      current.rows.push(line)
    } else {
      // lines before first header
      if (!sections.length) sections.push({ title: null, rows: [] })
      sections[0].rows.push(line)
    }
  }
  if (current) sections.push(current)

  return (
    <div style={{ background: '#1f1f23', border: '1px solid #3c4a42',
      borderRadius: 4, padding: '16px 20px' }}>
      <p style={{ fontSize: 10, fontWeight: 700, color: '#bbcabf',
        textTransform: 'uppercase', letterSpacing: '0.07em',
        fontFamily: 'JetBrains Mono, monospace', margin: '0 0 14px' }}>
        Score Breakdown
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {sections.map((section, si) => (
          <div key={si}>
            {section.title && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <div style={{ height: 1, flex: 1, background: '#3c4a42' }} />
                <span style={{ fontSize: 10, fontWeight: 700, color: '#4cd7f6',
                  textTransform: 'uppercase', letterSpacing: '0.08em',
                  fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap' }}>
                  {section.title}
                </span>
                <div style={{ height: 1, flex: 1, background: '#3c4a42' }} />
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {section.rows.map((line, i) => {
                const score  = parseScore(line)
                const color  = dotColor(line)
                const isZero = line.includes('→ +0') || line.includes('→ -0')
                // Strip the → +X part from display text
                const text   = line.trim().replace(/\s*→\s*[+-]\d+.*$/, '').trim()

                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center',
                    justifyContent: 'space-between', gap: 8,
                    padding: '4px 8px', borderRadius: 2,
                    background: !isZero && color && color !== '#86948a'
                      ? color + '0d' : 'transparent' }}>
                    <span style={{ fontSize: 11, color: '#bbcabf',
                      fontFamily: 'Geist, sans-serif', lineHeight: 1.4,
                      flex: 1 }}>
                      {text}
                    </span>
                    {score && (
                      <span style={{
                        fontSize: 11, fontWeight: 700,
                        fontFamily: 'JetBrains Mono, monospace',
                        color: isZero ? '#3c4a42' : color || '#86948a',
                        minWidth: 32, textAlign: 'right',
                        flexShrink: 0,
                      }}>
                        {score}
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
