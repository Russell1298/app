import type { SSLScanResult } from '@/types/scan'

export default function SslPanel({ data }: { data: SSLScanResult }) {
  const cert = data.certificate

  const expiryColor = cert
    ? cert.days_until_expiry < 14 ? 'text-red-400'
    : cert.days_until_expiry < 30 ? 'text-amber-400'
    : 'text-emerald-400'
    : 'text-gray-500'

  return (
    <div className="space-y-5">
      {/* Certificate info */}
      {cert && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Certificate</h4>
          <div className="bg-black/30 rounded-lg border border-gray-800 divide-y divide-gray-800">
            {[
              ['Subject', cert.subject],
              ['Issuer',  cert.issuer],
              ['Not before', cert.not_before],
              ['Not after',  cert.not_after],
              ['Days remaining', String(cert.days_until_expiry)],
              ['Self-signed', cert.is_self_signed ? 'Yes ⚠' : 'No ✓'],
              ['SANs', cert.sans.join(', ') || '—'],
            ].map(([label, value]) => (
              <div key={label} className="flex gap-3 px-4 py-2.5 text-xs">
                <span className="w-32 flex-shrink-0 text-gray-500">{label}</span>
                <span className={`mono flex-1 break-all ${label === 'Days remaining' ? expiryColor : 'text-gray-300'}`}>
                  {value}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TLS version matrix */}
      <div>
        <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">TLS Version Support</h4>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {data.tls_versions.map(v => {
            const good = (v.version === 'TLS 1.0' || v.version === 'TLS 1.1')
              ? !v.supported   // 1.0/1.1 should NOT be supported
              : v.supported === true
            const color = v.supported === null ? 'border-gray-700 text-gray-600'
              : good ? 'border-emerald-700 text-emerald-400 bg-emerald-900/20'
              : 'border-red-700 text-red-400 bg-red-900/20'
            const label = v.supported === null ? 'unknown'
              : v.supported ? 'enabled' : 'disabled'
            return (
              <div key={v.version} className={`rounded-lg border p-3 text-center ${color}`}>
                <p className="mono text-sm font-medium">{v.version}</p>
                <p className="text-xs mt-0.5 capitalize">{label}</p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Findings */}
      <div>
        <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Findings</h4>
        <div className="space-y-2">
          {data.findings.map((f, i) => {
            const statusColor = { pass: 'text-emerald-400', fail: 'text-red-400', warn: 'text-amber-400', info: 'text-gray-500' }[f.status]
            const statusIcon = { pass: '✓', fail: '✗', warn: '⚠', info: '·' }[f.status]
            return (
              <details key={i} className="group bg-black/20 rounded-lg border border-gray-800 overflow-hidden">
                <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/5 list-none">
                  <span className={`w-5 text-center font-mono ${statusColor}`}>{statusIcon}</span>
                  <span className="flex-1 text-sm text-gray-300">{f.check}</span>
                  {f.severity && (
                    <span className={`text-xs mono ${{high:'text-red-400',medium:'text-amber-400',low:'text-blue-400'}[f.severity]}`}>
                      {f.severity}
                    </span>
                  )}
                  <svg className="w-3 h-3 text-gray-600 group-open:rotate-180 transition-transform"
                    fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </summary>
                {(f.description || f.remediation) && (
                  <div className="px-4 pb-3 pt-1 border-t border-gray-800 space-y-2">
                    <p className="text-xs text-gray-400">{f.description}</p>
                    {f.remediation && (
                      <pre className="text-xs mono text-cyan-300 whitespace-pre-wrap bg-black/40 rounded p-2 border border-gray-800">
                        {f.remediation}
                      </pre>
                    )}
                  </div>
                )}
              </details>
            )
          })}
        </div>
      </div>
    </div>
  )
}
