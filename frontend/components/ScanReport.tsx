import type { FullScanResult } from '@/types/scan'
import RiskScore from './RiskScore'
import RiskBadge from './RiskBadge'
import TopFindings from './TopFindings'
import ScannerSection from './ScannerSection'
import HeadersPanel from './HeadersPanel'
import DnsPanel from './DnsPanel'
import SslPanel from './SslPanel'
import ExposurePanel from './ExposurePanel'
import FingerprintPanel from './FingerprintPanel'

export default function ScanReport({ result }: { result: FullScanResult }) {
  const ts = new Date(result.scan_timestamp).toLocaleString()

  return (
    <div className="space-y-6">
      {/* Header row */}
      <div className="card px-6 py-5">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-1 flex-wrap">
              <h2 className="text-xl font-bold text-white mono truncate">{result.domain}</h2>
              <RiskBadge level={result.overall_risk_level} />
            </div>
            <p className="text-xs text-gray-500">Scanned {ts}</p>
            {result.scan_id && (
              <div className="mt-2 flex items-center gap-2">
                <span className="text-xs text-gray-600">Shareable link:</span>
                <a
                  href={`/report/${result.scan_id}`}
                  className="text-xs mono text-cyan-500 hover:text-cyan-400 hover:underline"
                >
                  /report/{result.scan_id}
                </a>
              </div>
            )}
          </div>
          <RiskScore score={result.overall_risk_score} level={result.overall_risk_level} />
        </div>

        {/* Per-scanner score row */}
        <div className="mt-5 pt-4 border-t border-gray-800 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Headers', score: result.headers.risk_score,  level: result.headers.risk_level },
            { label: 'DNS',     score: result.dns.risk_score,      level: result.dns.risk_level },
            { label: 'SSL/TLS', score: result.ssl.risk_score,      level: result.ssl.risk_level },
            { label: 'Exposure',score: result.exposure.risk_score, level: result.exposure.risk_level },
          ].map(s => (
            <div key={s.label} className="text-center bg-black/20 rounded-lg p-3">
              <p className="text-xs text-gray-500 mb-1">{s.label}</p>
              <p className="mono text-lg font-bold text-gray-200">{s.score}</p>
              <RiskBadge level={s.level} className="mt-1" />
            </div>
          ))}
        </div>
      </div>

      {/* Top findings */}
      {result.top_findings.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-2">
            <span className="w-1.5 h-1.5 bg-red-400 rounded-full" />
            Priority Issues
          </h3>
          <TopFindings findings={result.top_findings} />
        </div>
      )}

      {/* Fingerprint quick summary */}
      {result.fingerprint.matches.length > 0 && (
        <div className="card px-5 py-3 flex items-center gap-3 flex-wrap">
          <span className="text-xs text-gray-500 uppercase tracking-wide">Detected stack</span>
          {result.fingerprint.matches.map(m => (
            <span key={m.name} className="text-xs mono text-gray-300 bg-gray-800 rounded px-2 py-0.5 border border-gray-700">
              {m.name}
            </span>
          ))}
        </div>
      )}

      {/* Scanner sections */}
      <div>
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-2">
          <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full" />
          Detailed Results
        </h3>
        <div className="space-y-3">
          <ScannerSection title="Security Headers" score={result.headers.risk_score} level={result.headers.risk_level} defaultOpen={result.headers.risk_score > 0}>
            <HeadersPanel data={result.headers} />
          </ScannerSection>
          <ScannerSection title="DNS & Email Authentication" score={result.dns.risk_score} level={result.dns.risk_level} defaultOpen={result.dns.risk_score > 20}>
            <DnsPanel data={result.dns} />
          </ScannerSection>
          <ScannerSection title="SSL / TLS" score={result.ssl.risk_score} level={result.ssl.risk_level} defaultOpen={result.ssl.risk_score > 20}>
            <SslPanel data={result.ssl} />
          </ScannerSection>
          <ScannerSection title="Public Exposure" score={result.exposure.risk_score} level={result.exposure.risk_level} defaultOpen={result.exposure.risk_score > 0}>
            <ExposurePanel data={result.exposure} />
          </ScannerSection>
          <ScannerSection title="Technology Fingerprint" score={0} level="low">
            <FingerprintPanel data={result.fingerprint} />
          </ScannerSection>
        </div>
      </div>
    </div>
  )
}
