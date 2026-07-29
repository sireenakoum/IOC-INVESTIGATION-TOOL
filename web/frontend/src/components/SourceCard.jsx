const CARD = {
  background: '#1f1f23',
  border: '1px solid #3c4a42',
  borderRadius: 4,
  padding: '16px 20px',
}

const SectionTitle = ({ source, aspect }) => (
  <p style={{
    fontSize: 10, fontWeight: 700, color: '#bbcabf',
    textTransform: 'uppercase', letterSpacing: '0.07em',
    fontFamily: 'JetBrains Mono, monospace',
    margin: '0 0 12px',
  }}>
    {source} — {aspect}
  </p>
)

const Label = ({ children }) => (
  <p style={{ fontSize: 11, color: '#86948a', margin: '0 0 2px', fontFamily: 'Geist, sans-serif' }}>{children}</p>
)

const Value = ({ children }) => (
  <p style={{ fontSize: 13, color: '#e3e2e6', fontWeight: 600, margin: 0, fontFamily: 'Geist, sans-serif' }}>{children}</p>
)

const Field = ({ label, value }) => !value && value !== 0 ? null : (
  <div><Label>{label}</Label><Value>{value}</Value></div>
)

const Grid = ({ children }) => (
  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 24px' }}>
    {children}
  </div>
)

const Tag = ({ children, color = '#4cd7f6' }) => (
  <span style={{
    background: color + '22', color,
    fontSize: 11, padding: '2px 8px', borderRadius: 2,
    fontFamily: 'JetBrains Mono, monospace',
    display: 'inline-block', margin: '2px 3px 2px 0',
  }}>{children}</span>
)

const LinkedTag = ({ children, color = '#4cd7f6', sources = [] }) => {
  if (!sources || sources.length === 0) return <Tag color={color}>{children}</Tag>
  const [firstUrl, ...rest] = sources
  const title = rest.length > 0
    ? `${firstUrl}\n\nAlso on:\n${rest.join('\n')}`
    : firstUrl
  return (
    <a href={firstUrl} target="_blank" rel="noopener noreferrer"
      title={title}
      style={{ textDecoration: 'none', display: 'inline-block', margin: '2px 3px 2px 0' }}>
      <span style={{
        background: color + '22', color,
        fontSize: 11, padding: '2px 8px', borderRadius: 2,
        fontFamily: 'JetBrains Mono, monospace',
        display: 'inline-flex', alignItems: 'center', gap: 3,
        textDecoration: 'underline', textDecorationStyle: 'dotted',
        textDecorationColor: color + '99',
      }}>
        {children}
        {rest.length > 0 && (
          <sup style={{ fontSize: 8, opacity: 0.7 }}>×{sources.length}</sup>
        )}
      </span>
    </a>
  )
}

const Table = ({ headers, rows }) => (
  <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
    <thead>
      <tr style={{ borderBottom: '1px solid #3c4a42' }}>
        {headers.map(h => (
          <th key={h} style={{ textAlign: 'left', padding: '4px 8px 6px 0',
            color: '#86948a', fontWeight: 500, fontFamily: 'Geist, sans-serif' }}>{h}</th>
        ))}
      </tr>
    </thead>
    <tbody>
      {rows.map((row, i) => (
        <tr key={i} style={{ borderBottom: '1px solid #292a2d' }}>
          {row.map((cell, j) => {
            const isMono = typeof cell === 'string'
              && (cell.includes('.') || /^[0-9a-f]{8,}/i.test(cell) || /^\d+$/.test(String(cell)))
            return (
              <td key={j} style={{ padding: '5px 8px 5px 0',
                color: isMono ? '#e3e2e6' : '#bbcabf',
                fontFamily: isMono ? 'JetBrains Mono, monospace' : 'Geist, sans-serif' }}>
                {cell}
              </td>
            )
          })}
        </tr>
      ))}
    </tbody>
  </table>
)

export function getSourceContainers(key, data, callbacks = {}) {
  if (!data) return []
  const containers = []

  // ── VIRUSTOTAL ──────────────────────────────────────────
  if (key === 'vt') {
    const total = (data.malicious||0)+(data.suspicious||0)+(data.harmless||0)+(data.undetected||0)
    const lastScan = data.last_scan_date
      ? new Date(data.last_scan_date * 1000).toISOString().slice(0,16).replace('T',' ')
      : null

    containers.push(
      <div style={CARD}>
        <SectionTitle source="VirusTotal" aspect="Detection Stats" />
        <Grid>
          <Field label="Malicious" value={`${data.malicious} / ${total} engines`} />
          <Field label="Suspicious" value={data.suspicious} />
          <Field label="Harmless" value={data.harmless} />
          <Field label="Undetected" value={data.undetected} />
          {data.country && <Field label="Country" value={data.country} />}
          {data.asn && <Field label="ASN" value={String(data.asn)} />}
          {lastScan && <Field label="Last Scan" value={lastScan} />}
        </Grid>
        {data.tags?.length > 0 && (
          <div style={{ marginTop: 10 }}>
            {data.tags.map((t,i) => <Tag key={i} color="#4cd7f6">{t}</Tag>)}
          </div>
        )}
      </div>
    )

    if (data.malicious_vendors?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="VirusTotal" aspect="Malicious Detections" />
          {data.malicious_vendors.map((v, i) => (
            <div key={i} style={{ display:'flex', justifyContent:'space-between',
              padding:'5px 0', borderBottom:'1px solid #292a2d', fontSize:12 }}>
              <span style={{ color:'#86948a', fontFamily:'Geist, sans-serif' }}>{v.vendor}</span>
              <span style={{ color:'#ffb4ab', fontFamily:'JetBrains Mono, monospace' }}>{v.name}</span>
            </div>
          ))}
        </div>
      )
    }

    if (data.dns_records?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="VirusTotal" aspect="DNS Records" />
          {data.dns_records.map((r, i) => (
            <p key={i} style={{ fontSize:11, color:'#bbcabf',
              fontFamily:'JetBrains Mono, monospace', margin:'3px 0' }}>{r}</p>
          ))}
        </div>
      )
    }

    if (data.comments?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="VirusTotal" aspect={`Community Comments (${data.comments.length})`} />
          {data.comments.slice(0,5).map((c,i) => (
            <div key={i} style={{ padding:'8px 0', borderBottom:'1px solid #292a2d' }}>
              <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                <span style={{ fontSize:11, color:'#86948a', fontFamily:'Geist, sans-serif' }}>{c.date} · @{c.author}</span>
                <span style={{ fontSize:11, color:'#86948a', fontFamily:'Geist, sans-serif' }}>+{c.votes_positive}/-{c.votes_negative}</span>
              </div>
              <p style={{ fontSize:12, color:'#bbcabf', margin:0, lineHeight:1.5, fontFamily:'Geist, sans-serif' }}>{c.text}</p>
            </div>
          ))}
        </div>
      )
    }

    const relations = data.relations || {}
    const relEntries = Object.entries(relations).filter(([,v]) => v?.length)
    if (relEntries.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="VirusTotal" aspect="Relations" />
          {relEntries.map(([name, items]) => (
            <div key={name} style={{ marginBottom: 12 }}>
              <p style={{ fontSize:10, fontWeight:700, color:'#86948a',
                textTransform:'uppercase', letterSpacing:'.07em',
                fontFamily:'JetBrains Mono, monospace', margin:'0 0 6px' }}>
                {name.replace(/_/g,' ')}
              </p>
              <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                {items.map((item, i) => {
                  const id = name==='resolutions'
                    ? (item.hostname||item.ip||'')
                    : (item.id||'').slice(0,24)
                  const mal = item.malicious||0
                  return (
                    <span key={i} style={{ background:'#292a2d', color:'#bbcabf',
                      fontSize:11, fontFamily:'JetBrains Mono, monospace', padding:'2px 8px',
                      borderRadius:2, display:'inline-flex', alignItems:'center', gap:4 }}>
                      {id}
                      {mal>0 && (
                        <span style={{ background:'#ffb4ab', color:'#690005',
                          fontSize:9, padding:'1px 5px', borderRadius:9999, fontWeight:700 }}>{mal}</span>
                      )}
                    </span>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )
    }
  }

  // ── OTX ─────────────────────────────────────────────────
  if (key === 'otx') {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="AlienVault OTX" aspect="Summary" />
        <Grid>
          <Field label="Pulse Count" value={data.pulse_count} />
          {data.reputation !== undefined && data.reputation !== 0 &&
            <Field label="Reputation" value={data.reputation} />}
          {data.reputation_threat_score != null &&
            <Field label="Threat Score" value={`${data.reputation_threat_score}/100`} />}
          {data.reputation_threat_type &&
            <Field label="Threat Type" value={data.reputation_threat_type} />}
          {data.country && <Field label="Country" value={data.country} />}
          {data.asn && <Field label="ASN" value={data.asn} />}
        </Grid>
        {data.indicator_description && (
          <p style={{ fontSize:12, color:'#86948a', fontStyle:'italic', marginTop:10, fontFamily:'Geist, sans-serif' }}>
            {data.indicator_description}
          </p>
        )}
      </div>
    )

    const pulses = data.pulses_detail?.length ? data.pulses_detail : (data.pulse_details||[])
    if (pulses.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="AlienVault OTX" aspect={`Pulses (${pulses.length})`} />
          {pulses.slice(0,5).map((p,i) => (
            <div key={i} style={{ background:'#292a2d', borderRadius:2, padding:12,
              marginBottom:8, border:'1px solid #3c4a42' }}>
              <p style={{ fontSize:13, fontWeight:600, color:'#e3e2e6', margin:'0 0 5px', fontFamily:'Geist, sans-serif' }}>
                {p.name||'Unnamed'}
              </p>
              {p.adversary && (
                <p style={{ fontSize:11, color:'#86948a', margin:'0 0 4px', fontFamily:'Geist, sans-serif' }}>
                  Adversary: {p.adversary}
                </p>
              )}
              {p.modified && (
                <p style={{ fontSize:11, color:'#86948a', margin:'0 0 4px', fontFamily:'Geist, sans-serif' }}>
                  Modified: {p.modified}
                </p>
              )}
              <div style={{ marginBottom:4 }}>
                {(p.malware_families||p.families||[]).map((f,j) =>
                  <Tag key={j} color="#ffb4ab">{f}</Tag>)}
                {(p.attack_ids||[]).map((a,j) =>
                  <Tag key={j} color="#c084fc">{a}</Tag>)}
                {(p.tags||[]).slice(0,6).map((t,j) =>
                  <Tag key={j} color="#86948a">{t}</Tag>)}
              </div>
              {p.description && (
                <p style={{ fontSize:11, color:'#86948a', margin:'4px 0 0', lineHeight:1.5, fontFamily:'Geist, sans-serif' }}>
                  {p.description.slice(0,200)}
                </p>
              )}
              {(Array.isArray(p.references) ? p.references[0] : p.ref) && (
                <a href={Array.isArray(p.references) ? p.references[0] : p.ref}
                  target="_blank" rel="noopener noreferrer"
                  style={{ fontSize:11, color:'#4cd7f6', display:'block', marginTop:4,
                    overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
                    fontFamily:'JetBrains Mono, monospace' }}>
                  {Array.isArray(p.references) ? p.references[0] : p.ref}
                </a>
              )}
            </div>
          ))}
        </div>
      )
    }

    if (data.passive_dns?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="AlienVault OTX" aspect={`Passive DNS (${data.passive_dns.length})`} />
          <Table
            headers={['Hostname','Address','Type','First','Last']}
            rows={data.passive_dns.slice(0,15).map(r => [
              r.hostname||'', r.address||'', r.record_type||'',
              r.first?.slice(0,10)||'', r.last?.slice(0,10)||''
            ])}
          />
        </div>
      )
    }
  }

  // ── ABUSEIPDB ───────────────────────────────────────────
  if (key === 'abuse' && data.total_reports > 0) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="AbuseIPDB" aspect="Abuse Summary" />
        <Grid>
          <Field label="Abuse Score" value={`${data.abuse_score}%`} />
          <Field label="Total Reports" value={`${data.total_reports} (${data.distinct_users} users)`} />
          <Field label="ISP" value={data.isp} />
          <Field label="Country" value={data.country} />
          <Field label="Tor Exit Node" value={data.is_tor ? 'Yes' : 'No'} />
          {data.last_reported && <Field label="Last Reported" value={data.last_reported.slice(0,10)} />}
        </Grid>
      </div>
    )

    if (data.top_categories?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="AbuseIPDB" aspect="Attack Categories" />
          {data.top_categories.slice(0,8).map(([name, count], i) => (
            <div key={i} style={{ display:'flex', justifyContent:'space-between',
              padding:'4px 0', borderBottom:'1px solid #292a2d', fontSize:12 }}>
              <span style={{ color:'#86948a', fontFamily:'Geist, sans-serif' }}>{name}</span>
              <span style={{ color:'#e3e2e6', fontWeight:600, fontFamily:'JetBrains Mono, monospace' }}>{count}</span>
            </div>
          ))}
        </div>
      )
    }
  }

  // ── SHODAN ──────────────────────────────────────────────
  if (key === 'shodan' && (data.org || data.ports?.length)) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="Shodan" aspect="Host Info" />
        <Grid>
          <Field label="Org" value={data.org} />
          <Field label="ISP" value={data.isp} />
          <Field label="ASN" value={data.asn} />
          <Field label="Country" value={data.country} />
          <Field label="City" value={data.city} />
          <Field label="OS" value={data.os} />
          {data.last_update && <Field label="Last Scan" value={data.last_update.slice(0,10)} />}
        </Grid>
        {data.hostnames?.length > 0 && (
          <div style={{ marginTop:10 }}>
            <Label>Hostnames</Label>
            <div style={{ marginTop:4 }}>
              {data.hostnames.slice(0,5).map((h,i) => <Tag key={i} color="#86948a">{h}</Tag>)}
            </div>
          </div>
        )}
        {data.tags?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {data.tags.map((t,i) => <Tag key={i} color="#4cd7f6">{t}</Tag>)}
          </div>
        )}
      </div>
    )

    if (data.ports?.length > 0 || data.services?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Shodan" aspect="Ports & Services" />
          {data.ports?.length > 0 && (
            <div style={{ marginBottom:12 }}>
              <Label>Open Ports</Label>
              <div style={{ marginTop:4 }}>
                {data.ports.map((p,i) => <Tag key={i} color="#4cd7f6">{p}</Tag>)}
              </div>
            </div>
          )}
          {data.services?.length > 0 && (
            <Table
              headers={['Port','Proto','Product','Version']}
              rows={data.services.map(s => [s.port, s.transport, s.product||'—', s.version||'—'])}
            />
          )}
        </div>
      )
    }

    if (data.vulns?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Shodan" aspect={`CVEs (${data.vulns.length})`} />
          <div>
            {data.vulns.map((v,i) => <Tag key={i} color="#ffb4ab">{v}</Tag>)}
          </div>
        </div>
      )
    }
  }

  // ── CENSYS ──────────────────────────────────────────────
  if (key === 'censys' && (data.org || data.ports?.length)) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="Censys" aspect="Host Info" />
        <Grid>
          <Field label="Org" value={data.org} />
          <Field label="ASN" value={data.asn} />
          <Field label="Country" value={data.country} />
          <Field label="OS" value={data.os} />
          {data.last_update && <Field label="Last Scan" value={data.last_update.slice(0,10)} />}
        </Grid>
        {data.labels?.length > 0 && (
          <div style={{ marginTop:10 }}>
            {data.labels.map((l,i) => <Tag key={i} color="#4cd7f6">{l}</Tag>)}
          </div>
        )}
      </div>
    )

    if (data.ports?.length > 0 || data.services?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Censys" aspect="Ports & Services" />
          {data.ports?.length > 0 && (
            <div style={{ marginBottom:12 }}>
              <Label>Open Ports</Label>
              <div style={{ marginTop:4 }}>
                {data.ports.map((p,i) => <Tag key={i} color="#4cd7f6">{p}</Tag>)}
              </div>
            </div>
          )}
          {data.services?.length > 0 && (
            <Table
              headers={['Port','Proto','Product','Version']}
              rows={data.services.map(s => [s.port, s.transport, s.product||'—', s.version||'—'])}
            />
          )}
        </div>
      )
    }

    if (data.vulns?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Censys" aspect={`CVEs (${data.vulns.length})`} />
          <div>
            {data.vulns.map((v,i) => <Tag key={i} color="#ffb4ab">{v}</Tag>)}
          </div>
        </div>
      )
    }
  }

  // ── WHOIS ───────────────────────────────────────────────
  if (key === 'whois' && data.registrar) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="WHOIS" aspect="Domain Registration" />
        <Grid>
          <Field label="Registrar" value={data.registrar} />
          <Field label="Country" value={data.country} />
          <Field label="Created" value={data.creation_date?.slice(0,10)} />
          <Field label="Expires" value={data.expiration_date?.slice(0,10)} />
          {data.domain_age_days != null &&
            <Field label="Domain Age" value={`${data.domain_age_days} days`} />}
          <Field label="Privacy Masked" value={data.privacy_masked ? 'Yes' : 'No'} />
        </Grid>
        {data.name_servers?.length > 0 && (
          <div style={{ marginTop:10 }}>
            <Label>Name Servers</Label>
            <div style={{ marginTop:4 }}>
              {data.name_servers.slice(0,6).map((ns,i) =>
                <Tag key={i} color="#86948a">{ns}</Tag>)}
            </div>
          </div>
        )}
      </div>
    )
  }

  // ── THREATFOX ───────────────────────────────────────────
  if (key === 'threatfox' && (data.malware || data.threat_type)) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="ThreatFox" aspect="Malware Info" />
        <Grid>
          {data.malware && (
            <Field label="Malware"
              value={`${data.malware}${data.malware_alias ? ` (${data.malware_alias})` : ''}`} />
          )}
          {data.threat_type && <Field label="Threat Type" value={data.threat_type} />}
          {data.first_seen && <Field label="First Seen" value={data.first_seen.slice(0,10)} />}
          {data.ioc_count != null && <Field label="IOC Count" value={data.ioc_count} />}
        </Grid>
        {data.confidence_level != null && (
          <div style={{ marginTop:10 }}>
            <Label>Confidence</Label>
            <div style={{ display:'flex', alignItems:'center', gap:8, marginTop:4 }}>
              <div style={{ flex:1, height:6, background:'#292a2d', borderRadius:9999 }}>
                <div style={{ width:`${data.confidence_level}%`, height:'100%',
                  background:'#ffb95f', borderRadius:9999 }} />
              </div>
              <span style={{ fontSize:12, color:'#e3e2e6', fontFamily:'JetBrains Mono, monospace' }}>{data.confidence_level}%</span>
            </div>
          </div>
        )}
        {data.tags?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {data.tags.map((t,i) => <Tag key={i} color="#86948a">{t}</Tag>)}
          </div>
        )}
      </div>
    )

    if (data.iocs?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="ThreatFox" aspect="IOC List" />
          <Table
            headers={['IOC','Type','Threat']}
            rows={data.iocs.map(ioc => [
              (ioc.ioc||'').slice(0,50),
              ioc.ioc_type||'',
              ioc.threat_type||''
            ])}
          />
        </div>
      )
    }
  }

  // ── URLHAUS ─────────────────────────────────────────────
  if (key === 'urlhaus' && data.url_count) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="URLhaus" aspect="Summary" />
        <Grid>
          <Field label="URL Count" value={data.url_count} />
          {data.threat && <Field label="Threat Type" value={data.threat} />}
          {data.first_seen && <Field label="First Seen" value={data.first_seen.slice(0,10)} />}
        </Grid>
      </div>
    )

    if (data.urls?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="URLhaus" aspect="Sample URLs" />
          {data.urls.slice(0,5).map((u,i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', gap:8,
              padding:'5px 0', borderBottom:'1px solid #292a2d', fontSize:11 }}>
              <span style={{
                background: u.url_status==='online' ? 'rgba(255,180,171,0.13)' : '#292a2d',
                color: u.url_status==='online' ? '#ffb4ab' : '#86948a',
                padding:'1px 6px', borderRadius:2, flexShrink:0, fontSize:10,
                fontFamily:'JetBrains Mono, monospace',
              }}>{u.url_status||'?'}</span>
              <span style={{ color:'#bbcabf', fontFamily:'JetBrains Mono, monospace',
                overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                {u.url}
              </span>
              <span style={{ color:'#86948a', flexShrink:0, fontFamily:'Geist, sans-serif' }}>
                {u.date_added?.slice(0,10)}
              </span>
            </div>
          ))}
        </div>
      )
    }
  }

  // ── GREYNOISE ───────────────────────────────────────────
  if (key === 'greynoise' && data.classification) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="GreyNoise" aspect="Classification" />
        <Grid>
          <Field label="Classification" value={data.classification} />
          <Field label="Noise" value={data.noise ? 'Yes — internet background noise' : 'No'} />
          {data.actor && <Field label="Actor" value={data.actor} />}
        </Grid>
        {data.tags?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {data.tags.map((t,i) => <Tag key={i} color="#86948a">{t}</Tag>)}
          </div>
        )}
        {data.cve?.length > 0 && (
          <div style={{ marginTop:8 }}>
            <Label>CVEs</Label>
            <div style={{ marginTop:4 }}>
              {data.cve.map((c,i) => <Tag key={i} color="#ffb4ab">{c}</Tag>)}
            </div>
          </div>
        )}
      </div>
    )
  }

  // ── URLSCAN ─────────────────────────────────────────────
  if (key === 'urlscan') {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="URLScan" aspect="Scan Result" />
        <Grid>
          <Field label="Malicious" value={data.malicious ? 'Yes' : 'No'} />
          {data.page_title && <Field label="Page Title" value={data.page_title} />}
          {data.server && <Field label="Server" value={data.server} />}
          {data.ip && <Field label="Resolved IP" value={data.ip} />}
        </Grid>
        {data.categories?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {data.categories.map((c,i) => <Tag key={i} color="#4cd7f6">{c}</Tag>)}
          </div>
        )}
        {data.domains?.length > 0 && (
          <div style={{ marginTop:10 }}>
            <Label>Related Domains</Label>
            <div style={{ marginTop:4 }}>
              {data.domains.slice(0,8).map((d,i) => <Tag key={i} color="#86948a">{d}</Tag>)}
            </div>
          </div>
        )}
      </div>
    )
  }

  // ── HYBRID ANALYSIS ─────────────────────────────────────
  if (key === 'hybrid' && data.verdict) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="Hybrid Analysis" aspect="Sandbox Result" />
        <Grid>
          <Field label="Threat Score" value={data.threat_score} />
          <Field label="Verdict" value={data.verdict} />
          {data.type && <Field label="File Type" value={data.type} />}
        </Grid>
        {data.family?.length > 0 && (
          <div style={{ marginTop:8 }}>
            {data.family.map((f,i) => <Tag key={i} color="#ffb4ab">{f}</Tag>)}
          </div>
        )}
      </div>
    )
  }

  // ── GOOGLE INTEL ────────────────────────────────────────
  if (key === 'google_intel') {
    const families     = data.malware_families||[]
    const attacks      = data.attack_ids||[]
    const aptActors    = data.apt_actors||[]
    const cveIds       = data.cve_ids||[]
    const severityHits = data.severity_hits||[]
    const co           = data.co_iocs||{}

    const evidSrc    = data.evidence_sources || {}
    const malwareSrc = evidSrc.malware    || {}
    const aptSrc     = evidSrc.apt_actors || {}
    const attckSrc   = evidSrc.attck      || {}
    const cveSrc     = evidSrc.cves       || {}
    const sevSrc     = evidSrc.severity   || {}
    const coIocSrc   = evidSrc.co_iocs   || {}

    if (families.length > 0 || attacks.length > 0 || aptActors.length > 0 || cveIds.length > 0 || severityHits.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Google Intel" aspect="Malware & ATT&CK" />
          {families.length > 0 && (
            <div style={{ marginBottom:10 }}>
              <Label>Malware Families</Label>
              <div style={{ marginTop:4 }}>
                {families.map((f,i) => <LinkedTag key={i} color="#ffb4ab" sources={malwareSrc[f]||[]}>{f}</LinkedTag>)}
              </div>
            </div>
          )}
          {aptActors.length > 0 && (
            <div style={{ marginBottom:10 }}>
              <Label>APT Actors</Label>
              <div style={{ marginTop:4 }}>
                {aptActors.map((a,i) => <LinkedTag key={i} color="#ef4444" sources={aptSrc[a]||[]}>{a}</LinkedTag>)}
              </div>
            </div>
          )}
          {attacks.length > 0 && (
            <div style={{ marginBottom:10 }}>
              <Label>ATT&amp;CK Techniques</Label>
              <div style={{ marginTop:4 }}>
                {attacks.map((a,i) => <LinkedTag key={i} color="#c084fc" sources={attckSrc[a]||[]}>{a}</LinkedTag>)}
              </div>
            </div>
          )}
          {cveIds.length > 0 && (
            <div style={{ marginBottom:10 }}>
              <Label>CVEs Mentioned</Label>
              <div style={{ marginTop:4 }}>
                {cveIds.map((c,i) => <LinkedTag key={i} color="#f97316" sources={cveSrc[c]||[]}>{c}</LinkedTag>)}
              </div>
            </div>
          )}
          {severityHits.length > 0 && (
            <div>
              <Label>Severity Signals</Label>
              <div style={{ marginTop:4 }}>
                {severityHits.map((s,i) => <LinkedTag key={i} color="#eab308" sources={sevSrc[s]||[]}>{s}</LinkedTag>)}
              </div>
            </div>
          )}
        </div>
      )
    }

    if (co.ips?.length || co.domains?.length || co.hashes?.length) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Google Intel" aspect="Co-mentioned IOCs" />
          {co.ips?.length > 0 && (
            <div style={{ marginBottom:8 }}>
              <Label>IPs</Label>
              <div style={{ marginTop:4 }}>
                {co.ips.map((ip,i) => <LinkedTag key={i} color="#4cd7f6" sources={coIocSrc[ip]||[]}>{ip}</LinkedTag>)}
              </div>
            </div>
          )}
          {co.domains?.length > 0 && (
            <div style={{ marginBottom:8 }}>
              <Label>Domains</Label>
              <div style={{ marginTop:4 }}>
                {co.domains.map((d,i) => <LinkedTag key={i} color="#86948a" sources={coIocSrc[d.toLowerCase()]||[]}>{d}</LinkedTag>)}
              </div>
            </div>
          )}
          {co.hashes?.length > 0 && (
            <div>
              <Label>Hashes</Label>
              <div style={{ marginTop:4 }}>
                {co.hashes.map((h,i) =>
                  <LinkedTag key={i} color="#86948a" sources={coIocSrc[h.toLowerCase()]||[]}>{h.slice(0,16)}…</LinkedTag>)}
              </div>
            </div>
          )}
        </div>
      )
    }

    if (data.urls_fetched?.length > 0) {
      containers.push(
        <div style={CARD}>
          <SectionTitle source="Google Intel" aspect={`Sources Fetched (${data.urls_fetched.length})`} />
          {data.urls_fetched.map((url,i) => {
            const tier = data.source_tiers?.[url]
            return (
              <div key={i} style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                {tier && (
                  <span style={{
                    background: tier===1?'rgba(78,222,163,0.13)':tier===2?'rgba(76,215,246,0.13)':'#292a2d',
                    color: tier===1?'#4edea3':tier===2?'#4cd7f6':'#86948a',
                    fontSize:10, padding:'1px 6px', borderRadius:2, flexShrink:0,
                    fontFamily:'JetBrains Mono, monospace',
                  }}>T{tier}</span>
                )}
                <a href={url} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize:11, color:'#4cd7f6', overflow:'hidden',
                    textOverflow:'ellipsis', whiteSpace:'nowrap',
                    fontFamily:'JetBrains Mono, monospace' }}>{url}</a>
              </div>
            )
          })}
        </div>
      )
    }
  }

  // ── PIVOT SCAN ──────────────────────────────────────────
  if (key === 'pivot') {
    const verdicts     = data.pivot_verdicts     || {}
    const scores       = data.pivot_scores       || {}
    const sourcesMap   = data.sources_map        || {}
    const breakdown    = data.breakdown          || []
    const pivotIocs    = data.pivot_iocs         || []
    const fromHistory  = data.pivot_from_full_scan || {}
    const onRescanPivot = callbacks.onRescanPivot

    containers.push(
      <div style={CARD}>
        <SectionTitle source="Pivot Scan" aspect={
          pivotIocs.length > 0
            ? `${pivotIocs.length} Related IOC${pivotIocs.length !== 1 ? 's' : ''} Found`
            : 'No Related IOCs Found'
        } />

        {breakdown.map((line, i) => (
          <p key={i} style={{ fontSize: 12, color: '#bbcabf',
            fontFamily: 'Geist, sans-serif', margin: '2px 0' }}>{line}</p>
        ))}

        {pivotIocs.length === 0 && breakdown.length === 0 && (
          <p style={{ fontSize: 12, color: '#86948a',
            fontFamily: 'Geist, sans-serif', margin: '4px 0' }}>
            No related infrastructure found.
          </p>
        )}

        {Object.keys(verdicts).length > 0 && (
          <table style={{ width: '100%', fontSize: 11,
            borderCollapse: 'collapse', marginTop: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #3c4a42' }}>
                {['IOC', 'Verdict', 'Score', 'Found by', 'Status', ''].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '4px 8px 6px 0',
                    color: '#86948a', fontWeight: 500,
                    fontFamily: 'Geist, sans-serif' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(verdicts).map(([ioc, verdict], i) => {
                const color = {
                  high:        '#ffb4ab',
                  medium_risk: '#f97316',
                  low_risk:    '#eab308',
                  suspicious:  '#f59e0b',
                  clean:       '#4edea3',
                }[verdict] || '#86948a'
                const historyTimestamp = fromHistory[ioc]
                return (
                  <tr key={i} style={{ borderBottom: '1px solid #292a2d' }}>
                    <td style={{ padding: '5px 8px 5px 0', color: '#e3e2e6',
                      fontFamily: 'JetBrains Mono, monospace',
                      maxWidth: 200, overflow: 'hidden',
                      textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc}</td>
                    <td style={{ padding: '5px 8px 5px 0',
                      color, fontWeight: 600, fontSize: 11 }}>
                      {verdict.replace(/_/g, ' ').toUpperCase()}
                    </td>
                    <td style={{ padding: '5px 8px 5px 0', color: '#bbcabf' }}>
                      {scores[ioc] ?? '—'}
                    </td>
                    <td style={{ padding: '5px 0', color: '#86948a', fontSize: 11 }}>
                      {(sourcesMap[ioc] || []).join(', ')}
                    </td>
                    <td style={{ padding: '5px 8px 5px 0' }}>
                      {historyTimestamp ? (
                        <span title={`Reused from a full scan completed ${historyTimestamp} — not a fresh pivot scan.`}
                          style={{
                            background: '#4cd7f622', color: '#4cd7f6',
                            fontSize: 10, fontWeight: 700, padding: '2px 7px',
                            borderRadius: 2, fontFamily: 'JetBrains Mono, monospace',
                            whiteSpace: 'nowrap', display: 'inline-block',
                          }}>
                          FROM HISTORY · {historyTimestamp.slice(0, 10)}
                        </span>
                      ) : (
                        <span style={{
                          background: '#4edea322', color: '#4edea3',
                          fontSize: 10, fontWeight: 700, padding: '2px 7px',
                          borderRadius: 2, fontFamily: 'JetBrains Mono, monospace',
                          whiteSpace: 'nowrap', display: 'inline-block',
                        }}>
                          PIVOT SCAN
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '5px 0 5px 8px' }}>
                      {historyTimestamp && onRescanPivot && (
                        <button
                          onClick={() => onRescanPivot(ioc)}
                          title="Run a fresh full scan on this IOC now"
                          className="transition-all active:scale-95"
                          style={{
                            background: 'transparent', border: '1px solid #3c4a42',
                            borderRadius: 2, color: '#bbcabf', cursor: 'pointer',
                            padding: '3px 8px', fontSize: 10, fontWeight: 600,
                            fontFamily: 'JetBrains Mono, monospace', whiteSpace: 'nowrap',
                          }}>
                          RESCAN
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}

        {callbacks.onViewPivot && (
          <div style={{ marginTop: 14, textAlign: 'right' }}>
            <button
              onClick={() => callbacks.onViewPivot(callbacks.scanIndicator || '')}
              title="Open the full pivot map for this indicator"
              className="transition-all active:scale-95"
              style={{
                background: 'transparent', border: '1px solid #3c4a42',
                borderRadius: 2, color: '#4cd7f6', cursor: 'pointer',
                padding: '6px 14px', fontSize: 11, fontWeight: 700,
                fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.05em',
              }}>
              VIEW PIVOT MAP →
            </button>
          </div>
        )}
      </div>
    )
  }

  // ── SPAMHAUS DROP ───────────────────────────────────────
  if (key === 'spamhaus_drop' && data.listed) {
    containers.push(
      <div style={CARD}>
        <SectionTitle source="Spamhaus DROP" aspect="ASN Listing" />
        <Grid>
          <Field label="Listed" value="Yes" />
          <Field label="ASN Name" value={data.asname} />
          <Field label="Country" value={data.cc} />
          <Field label="Domain" value={data.domain} />
          <Field label="RIR" value={data.rir} />
        </Grid>
      </div>
    )
  }

  return containers
}
