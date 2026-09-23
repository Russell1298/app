import type { TopFinding } from '@/types/scan'

const severityStyle = {
  high:   { dot: 'bg-red-400',    text: 'text-red-400',    badge: 'bg-red-900/40 text-red-300 border-red-800' },
  medium: { dot: 'bg-amber-400',  text: 'text-amber-400',  badge: 'bg-amber-900/40 text-amber-300 border-amber-800' },
  low:    { dot: 'bg-blue-400',   text: 'text-blue-400',   badge: 'bg-blue-900/40 text-blue-300 border-blue-800' },
}

const scannerLabel: Record<string, string> = {
  headers:     'Headers',
  dns:         'DNS',
  ssl:         'SSL/TLS',
  exposure:    'Exposure',
  fingerprint: 'Fingerprint',
}

export default function TopFindings({ findings }: { findings: TopFinding[] }) {
  if (findings.length === 0) {
    return (
      <div className="card px-5 py-6 text-center text-emerald-400 text-sm">
        No significant issues found. Good posture!
      </div>
    )
  }

  return (
    <div className="card divide-y divide-gray-800">
      {findings.map((f, i) => {
        const s = severityStyle[f.severity]
        return (
          <details key={i} className="group">
            <summary className="flex items-center gap-3 px-5 py-3.5 cursor-pointer hover:bg-white/5 transition-colors list-none">
              <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
              <span className="flex-1 text-sm text-gray-200 font-medium">{f.title}</span>
              <span className={`text-xs px-2 py-0.5 rounded border mono ${s.badge}`}>
                {f.severity.toUpperCase()}
              </span>
              <span className="text-xs text-gray-600 w-20 text-right">{scannerLabel[f.scanner]}</span>
              <svg className="w-3.5 h-3.5 text-gray-600 group-open:rotate-180 transition-transform flex-shrink-0"
                fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </summary>
            <div className="px-5 pb-4 pt-1 bg-black/20 space-y-2">
              <p className="text-sm text-gray-400">{f.description}</p>
              {f.remediation && (
                <div className="mt-2">
                  <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Fix</p>
                  <pre className="text-xs mono text-cyan-300 whitespace-pre-wrap bg-black/40 rounded p-3 border border-gray-800">
                    {f.remediation}
                  </pre>
                </div>
              )}
            </div>
          </details>
        )
      })}
    </div>
  )
}
