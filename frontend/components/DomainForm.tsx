'use client'

import { useState, useRef } from 'react'
import { runFullScan } from '@/lib/api'
import type { FullScanResult } from '@/types/scan'
import ScanReport from './ScanReport'

const SCAN_STEPS = [
  'Resolving DNS records',
  'Analysing security headers',
  'Inspecting TLS certificate',
  'Probing TLS version support',
  'Checking exposure paths',
  'Fingerprinting technologies',
  'Scoring and aggregating findings',
]

function cleanDomain(raw: string): string {
  return raw.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .split('?')[0]
}

export default function DomainForm() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<FullScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [stepIndex, setStepIndex] = useState(0)
  const resultRef = useRef<HTMLDivElement>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const startStepTimer = () => {
    let i = 0
    timerRef.current = setInterval(() => {
      i++
      setStepIndex(i)
    }, 1400)
  }

  const stopStepTimer = () => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const cleaned = cleanDomain(domain)
    if (!cleaned) return

    setDomain(cleaned)
    setResult(null)
    setError(null)
    setLoading(true)
    setStepIndex(0)
    startStepTimer()

    try {
      const data = await runFullScan(cleaned)
      setResult(data)
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed. Check the domain and try again.')
    } finally {
      stopStepTimer()
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      {/* Input form */}
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3 max-w-2xl mx-auto">
        <div className="relative flex-1">
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            placeholder="example.com"
            disabled={loading}
            spellCheck={false}
            autoCapitalize="none"
            autoCorrect="off"
            className="w-full bg-[#131620] border border-gray-700 rounded-xl px-4 py-3 mono text-gray-100
                       placeholder-gray-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40
                       disabled:opacity-50 transition-colors text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !domain.trim()}
          className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-gray-700 disabled:text-gray-500
                     text-black font-semibold rounded-xl transition-colors whitespace-nowrap text-sm"
        >
          {loading ? 'Scanning…' : 'Scan →'}
        </button>
      </form>

      <p className="text-center text-xs text-gray-600 -mt-4">
        Passive scan only · No exploitation · No brute forcing
      </p>

      {/* Loading state */}
      {loading && (
        <div className="card max-w-md mx-auto px-6 py-6">
          <p className="text-sm text-gray-400 mb-4 flex items-center gap-2">
            <span className="inline-block w-3 h-3 rounded-full bg-cyan-500 animate-ping" />
            Scanning <span className="mono text-cyan-300">{domain}</span>
          </p>
          <div className="space-y-2">
            {SCAN_STEPS.map((step, i) => {
              const done    = i < stepIndex
              const current = i === stepIndex
              return (
                <div
                  key={step}
                  style={{ animationDelay: `${i * 0.08}s` }}
                  className={`scan-item flex items-center gap-2.5 text-xs
                    ${done    ? 'text-emerald-400' : ''}
                    ${current ? 'text-cyan-300'    : ''}
                    ${!done && !current ? 'text-gray-700' : ''}
                  `}
                >
                  {done    && <span className="w-3.5 text-center">✓</span>}
                  {current && <span className="w-3.5 text-center animate-spin inline-block">⟳</span>}
                  {!done && !current && <span className="w-3.5 text-center">·</span>}
                  <span className="mono">{step}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="card max-w-xl mx-auto px-5 py-4 border-red-900/60 bg-red-950/20">
          <p className="text-red-400 text-sm font-medium mb-1">Scan failed</p>
          <p className="text-red-300/70 text-xs mono">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div ref={resultRef}>
          <ScanReport result={result} />
        </div>
      )}
    </div>
  )
}
