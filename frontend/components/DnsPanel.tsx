import type { DNSScanResult } from '@/types/scan'

const statusIcon: Record<string, string> = {
  pass: '✓',
  fail: '✗',
  warn: '⚠',
  info: '·',
}
const statusColor: Record<string, string> = {
  pass: 'text-emerald-400',
  fail: 'text-red-400',
  warn: 'text-amber-400',
  info: 'text-gray-500',
}

export default function DnsPanel({ data }: { data: DNSScanResult }) {
  return (
    <div className="space-y-5">
      {/* Records */}
      {data.records.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">DNS Records</h4>
          <div className="space-y-2">
            {data.records.map((r, i) => (
              <div key={i} className="bg-black/30 rounded-lg p-3 border border-gray-800">
                <span className="mono text-xs text-cyan-400 font-medium">{r.record_type}</span>
                <div className="mt-1 space-y-0.5">
                  {r.values.slice(0, 5).map((v, j) => (
                    <p key={j} className="mono text-xs text-gray-400 truncate">{v}</p>
                  ))}
                  {r.values.length > 5 && (
                    <p className="text-xs text-gray-600">+{r.values.length - 5} more</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings */}
      <div>
        <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Security Checks</h4>
        <div className="space-y-2">
          {data.findings.map((f, i) => (
            <details key={i} className="group bg-black/20 rounded-lg border border-gray-800 overflow-hidden">
              <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/5 transition-colors list-none">
                <span className={`font-mono text-base w-5 text-center ${statusColor[f.status]}`}>
                  {statusIcon[f.status]}
                </span>
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
              <div className="px-4 pb-3 pt-1 border-t border-gray-800 space-y-2">
                <p className="text-xs text-gray-400">{f.description}</p>
                {f.remediation && (
                  <pre className="text-xs mono text-cyan-300 whitespace-pre-wrap bg-black/40 rounded p-2 border border-gray-800">
                    {f.remediation}
                  </pre>
                )}
              </div>
            </details>
          ))}
        </div>
      </div>
    </div>
  )
}
