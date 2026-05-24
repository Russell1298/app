import type { ExposureScanResult } from '@/types/scan'

const severityStyle = {
  high:   'text-red-400',
  medium: 'text-amber-400',
  low:    'text-blue-400',
  info:   'text-gray-500',
}

export default function ExposurePanel({ data }: { data: ExposureScanResult }) {
  const exposed200  = data.findings.filter(f => f.exposed && f.status_code === 200 && f.severity !== 'info')
  const blocked403  = data.findings.filter(f => f.exposed && f.status_code === 403)
  const info        = data.findings.filter(f => f.severity === 'info' && f.status_code === 200)
  const clean       = data.findings.filter(f => !f.exposed)

  return (
    <div className="space-y-5">
      {/* Genuinely exposed */}
      {exposed200.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-red-500 mb-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
            Exposed ({exposed200.length})
          </h4>
          <div className="space-y-2">
            {exposed200.map((f, i) => (
              <details key={i} className="group bg-red-950/20 rounded-lg border border-red-900/50 overflow-hidden">
                <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/5 list-none">
                  <span className="mono text-xs text-red-300 flex-shrink-0">{f.status_code}</span>
                  <span className="mono text-xs text-gray-300 flex-1">{f.path}</span>
                  <span className={`text-xs ${severityStyle[f.severity]}`}>{f.severity}</span>
                  <svg className="w-3 h-3 text-gray-600 group-open:rotate-180 transition-transform"
                    fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </summary>
                <div className="px-4 pb-3 pt-1 border-t border-red-900/40 space-y-2">
                  <p className="text-xs font-medium text-red-300">{f.label}</p>
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
      )}

      {/* Informational (robots.txt, security.txt) */}
      {info.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Informational</h4>
          <div className="space-y-2">
            {info.map((f, i) => (
              <details key={i} className="group bg-black/20 rounded-lg border border-gray-800 overflow-hidden">
                <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/5 list-none">
                  <span className="mono text-xs text-gray-500 flex-shrink-0">{f.status_code}</span>
                  <span className="mono text-xs text-gray-400 flex-1">{f.path}</span>
                  <span className="text-xs text-gray-600">info</span>
                  <svg className="w-3 h-3 text-gray-600 group-open:rotate-180 transition-transform"
                    fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </summary>
                <div className="px-4 pb-3 pt-1 border-t border-gray-800">
                  <p className="text-xs text-gray-400">{f.description}</p>
                </div>
              </details>
            ))}
          </div>
        </div>
      )}

      {/* Blocked but present */}
      {blocked403.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-gray-600 mb-2">
            Blocked by config — 403 ({blocked403.length})
          </h4>
          <div className="flex flex-wrap gap-2">
            {blocked403.map((f, i) => (
              <span key={i} className="mono text-xs text-gray-600 bg-black/30 border border-gray-800 rounded px-2 py-1">
                {f.path}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Clean paths */}
      {clean.length > 0 && exposed200.length === 0 && blocked403.length === 0 && (
        <p className="text-sm text-emerald-400 text-center py-2">No sensitive paths are publicly accessible.</p>
      )}

      <p className="text-xs text-gray-600 text-right mono">
        {data.summary.paths_checked} paths checked
      </p>
    </div>
  )
}
