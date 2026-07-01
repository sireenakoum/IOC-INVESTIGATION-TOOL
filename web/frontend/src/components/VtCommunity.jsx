export default function VtCommunity({ vt }) {
  if (!vt) return null
  const comments   = vt.comments  || []
  const relations  = vt.relations  || {}
  const relEntries = Object.entries(relations).filter(([,v]) => v?.length)

  const sectionStyle = {
    background: '#1f1f23', border: '1px solid #3c4a42',
    borderRadius: 4, overflow: 'hidden',
  }
  const summaryStyle = {
    padding: '14px 20px', display: 'flex', alignItems: 'center',
    justifyContent: 'space-between', cursor: 'pointer',
    color: '#bbcabf', fontSize: 13, fontWeight: 500,
    userSelect: 'none', fontFamily: 'Geist, sans-serif',
  }
  const innerStyle = { borderTop: '1px solid #3c4a42', padding: '16px 20px' }

  return (
    <div className="space-y-2">

      {/* Comments */}
      <div style={sectionStyle}>
        <details>
          <summary style={summaryStyle}>
            <span>Community comments ({comments.length})</span>
            <span style={{ fontSize: 11, color: '#4cd7f6' }}>▾</span>
          </summary>
          <div style={innerStyle}>
            {comments.length === 0
              ? <p style={{ color: '#86948a', fontSize: 12, margin: 0, fontFamily: 'Geist, sans-serif' }}>No comments</p>
              : comments.map((c, i) => (
                <div key={i} style={{
                  marginBottom: i < comments.length-1 ? 14 : 0,
                  paddingBottom: i < comments.length-1 ? 14 : 0,
                  borderBottom: i < comments.length-1 ? '1px solid #3c4a42' : 'none',
                }}>
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom: 5 }}>
                    <span style={{ color: '#86948a', fontSize: 11, fontFamily: 'Geist, sans-serif' }}>
                      {c.date} · @{c.author}
                    </span>
                    <span style={{ color: '#86948a', fontSize: 11, fontFamily: 'Geist, sans-serif' }}>
                      +{c.votes_positive} / -{c.votes_negative}
                    </span>
                  </div>
                  <p style={{ color: '#bbcabf', fontSize: 13, margin: 0, lineHeight: 1.55, fontFamily: 'Geist, sans-serif' }}>
                    {c.text}
                  </p>
                </div>
              ))
            }
          </div>
        </details>
      </div>

      {/* Relations */}
      <div style={sectionStyle}>
        <details>
          <summary style={summaryStyle}>
            <span>Relations</span>
            <span style={{ fontSize: 11, color: '#4cd7f6' }}>▾</span>
          </summary>
          <div style={innerStyle}>
            {relEntries.length === 0
              ? <p style={{ color: '#86948a', fontSize: 12, margin: 0, fontFamily: 'Geist, sans-serif' }}>No relations</p>
              : relEntries.map(([name, items]) => (
                <div key={name} style={{ marginBottom: 14 }}>
                  <p style={{
                    color: '#bbcabf', fontSize: 10, fontWeight: 700,
                    textTransform: 'uppercase', letterSpacing: '.07em',
                    margin: '0 0 7px', fontFamily: 'JetBrains Mono, monospace',
                  }}>
                    {name.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}
                  </p>
                  <div style={{ display:'flex', flexWrap:'wrap', gap: 6 }}>
                    {items.map((item, i) => {
                      const id = name === 'resolutions'
                        ? (item.hostname || item.ip || '')
                        : (item.id || '').slice(0,20) + ((item.id||'').length>20?'…':'')
                      const mal = item.malicious || 0
                      return (
                        <span key={i} style={{
                          background: '#292a2d', color: '#bbcabf',
                          fontSize: 11, fontFamily: 'JetBrains Mono, monospace',
                          padding: '3px 8px', borderRadius: 2,
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                        }}>
                          {id}
                          {mal > 0 && (
                            <span style={{
                              background: '#ffb4ab', color: '#690005',
                              fontSize: 9, padding: '1px 5px',
                              borderRadius: 9999, fontWeight: 700,
                            }}>{mal}</span>
                          )}
                        </span>
                      )
                    })}
                  </div>
                </div>
              ))
            }
          </div>
        </details>
      </div>

    </div>
  )
}
