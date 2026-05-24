'use client'
import { useState } from 'react'
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

function ReportButtons({ scanId, domain }: { scanId: string; domain: string }) {
  const [clientName, setClientName] = useState('')
  const [showInput, setShowInput] = useState(false)

  const params = clientName ? `?client_name=${encodeURIComponent(clientName)}` : ''
  const base = `/api/v1/scans/${scanId}`

  return (
    <div className="flex flex-col items-center gap-2 w-full">
      {showInput ? (
        <div className="flex flex-col gap-2 w-full">
          <input
            type="text"
            placeholder="Client / company name (optional)"
            value={clientName}
            onChange={e => setClientName(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200
                       placeholder-gray-600 focus:outline-none focus:border-cyan-500"
          />
          <div className="flex gap-2">
            <a
              href={`${base}/report.pdf${params}`}
              target="_blank"
              rel="noreferrer"
              className="flex-1 text-center text-xs py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-semibold transition-colors"
            >
              ⬇ PDF
            </a>
            <a
              href={`${base}/report${params}`}
              target="_blank"
              rel="noreferrer"
              className="flex-1 text-center text-xs py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg font-semibold transition-colors"
            >
              ⬇ HTML
            </a>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setShowInput(true)}
          className="text-xs px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-semibold transition-colors w-full"
        >
          ⬇ Download Report
        </button>
      )}
    </div>
  )
}

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
              <div className="mt-2 flex items-center gap-2 flex-wrap">
                <span className="text-xs text-gray-600">Shareable:</span>
                <a
                  href={`/report/${result.scan_id}`}
                  className="text-xs mono text-cyan-500 hover:text-cyan-400 hover:underline"
                >
                  /report/{result.scan_id}
                </a>
              </div>
            )}
          </div>
          <div className="flex flex-col items-center gap-3">
            <RiskScore score={result.overall_risk_score} level={result.overall_risk_level} />
            {result.scan_id && (
              <ReportButtons scanId={result.scan_id} domain={result.domain} />
            )}
          </div>
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
