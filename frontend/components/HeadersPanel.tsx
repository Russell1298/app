import type { HeaderScanResult } from '@/types/scan'

const statusIcon = {
  present: <span className="text-emerald-400 text-lg">✓</span>,
  missing: <span className="text-red-400 text-lg">✗</span>,
  weak:    <span className="text-amber-400 text-lg">⚠</span>,
}

const severityStyle = {
  high:   'text-red-400',
  medium: 'text-amber-400',
  low:    'text-blue-400',
}

export default function HeadersPanel({ data }: { data: HeaderScanResult }) {
  return (
    <div className="space-y-5">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 text-xs uppercase tracking-wide border-b border-gray-800">
              <th className="pb-2 w-8"></th>
              <th className="pb-2">Header</th>
              <th className="pb-2">Severity</th>
              <th className="pb-2">Value</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {data.findings.map((f, i) => (
              <tr key={i} className="group">
                <td className="py-3 pr-3">{statusIcon[f.status]}</td>
                <td className="py-3 mono text-gray-200 text-xs">{f.header}</td>
                <td className={`py-3 text-xs font-medium ${severityStyle[f.severity]}`}>
                  {f.severity}
                </td>
                <td className="py-3 mono text-xs text-gray-500 max-w-xs truncate">
                  {f.value ?? <span className="text-gray-700 italic">not set</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data.information_leaks.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Information Leaks</h4>
          <div className="space-y-2">
            {data.information_leaks.map((leak, i) => (
              <div key={i} className="bg-black/30 rounded-lg p-3 border border-amber-900/40">
                <div className="flex items-center gap-2 mb-1">
                  <span className="mono text-xs text-amber-300">{leak.header}</span>
                  <span className={`text-xs ${severityStyle[leak.severity]}`}>{leak.severity}</span>
                </div>
                <p className="mono text-xs text-gray-400 mb-1">{leak.value}</p>
                <p className="text-xs text-gray-500">{leak.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
