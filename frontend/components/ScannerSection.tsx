'use client'

import { useState } from 'react'
import type { RiskLevel } from '@/types/scan'
import RiskBadge from './RiskBadge'

export default function ScannerSection({
  title,
  score,
  level,
  children,
  defaultOpen = false,
  badge,
}: {
  title: string
  score: number
  level: RiskLevel
  children: React.ReactNode
  defaultOpen?: boolean
  badge?: string
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/5 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <span className="font-semibold text-gray-200">{title}</span>
          <RiskBadge level={level} />
          {badge && (
            <span className="text-xs mono text-gray-400 bg-gray-800 border border-gray-700 rounded px-2 py-0.5">{badge}</span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="mono text-sm text-gray-400">{score}<span className="text-gray-600">/100</span></span>
          <svg
            className={`w-4 h-4 text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`}
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      {open && (
        <div className="border-t border-gray-800 px-5 py-4">
          {children}
        </div>
      )}
    </div>
  )
}
