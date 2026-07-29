export function guessIndicatorType(indicator) {
  if (!indicator) return 'Unknown'
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(indicator)) return 'IPv4'
  if (/^[0-9a-f]{32}$/i.test(indicator))          return 'MD5'
  if (/^[0-9a-f]{64}$/i.test(indicator))          return 'SHA256'
  if (/^[0-9a-f]{40}$/i.test(indicator))          return 'SHA1'
  return 'Domain'
}
