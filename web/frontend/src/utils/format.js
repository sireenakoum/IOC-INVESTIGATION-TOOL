export function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export function truncate(str, n = 20) {
  if (!str) return ''
  return str.length > n ? str.slice(0, n) + '…' : str
}
