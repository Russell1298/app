import type { FingerprintScanResult, FingerprintMatch } from '@/types/scan'

const categoryLabel: Record<FingerprintMatch['category'], string> = {
  cms:       'CMS',
  framework: 'Framework',
  cdn:       'CDN / Hosting',
  server:    'Web Server',
  library:   'JS Library',
}

const confidenceStyle = {
  high:   'text-emerald-400 border-emerald-800 bg-emerald-900/20',
  medium: 'text-amber-400   border-amber-800   bg-amber-900/20',
  low:    'text-gray-400    border-gray-700    bg-gray-800/40',
}

const categoryIcon: Record<FingerprintMatch['category'], string> = {
  cms:       '📄',
  framework: '⚙️',
  cdn:       '🌐',
  server:    '🖥',
  library:   '📦',
}

export default function FingerprintPanel({ data }: { data: FingerprintScanResult }) {
  if (data.matches.length === 0) {
    return (
      <p className="text-sm text-gray-500 text-center py-4">
        No technologies detected from headers or page source.
      </p>
    )
  }

  const grouped = data.matches.reduce<Record<string, FingerprintMatch[]>>((acc, m) => {
    acc[m.category] = acc[m.category] ?? []
    acc[m.category].push(m)
    return acc
  }, {})

  return (
    <div className="space-y-4">
      {(Object.keys(grouped) as FingerprintMatch['category'][]).map(cat => (
        <div key={cat}>
          <h4 className="text-xs uppercase tracking-wide text-gray-500 mb-2 flex items-center gap-1.5">
            <span>{categoryIcon[cat]}</span>
            {categoryLabel[cat]}
          </h4>
          <div className="space-y-2">
            {grouped[cat].map((m, i) => (
              <div key={i} className="bg-black/30 rounded-lg border border-gray-800 px-4 py-3 flex items-center justify-between gap-3">
                <span className="font-medium text-sm text-gray-200">{m.name}</span>
                <div className="flex items-center gap-2">
                  <span className={`text-xs mono px-2 py-0.5 rounded border ${confidenceStyle[m.confidence]}`}>
                    {m.confidence}
                  </span>
                  <span className="text-xs text-gray-600 hidden sm:block truncate max-w-xs" title={m.evidence}>
                    {m.evidence}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      <p className="text-xs text-gray-600 mono text-right">
        {data.matches.length} technolog{data.matches.length === 1 ? 'y' : 'ies'} detected
      </p>
    </div>
  )
}
