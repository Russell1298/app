import type { RiskLevel } from '@/types/scan'

const styles: Record<RiskLevel, string> = {
  low:      'bg-emerald-900/40 text-emerald-300 border-emerald-700',
  medium:   'bg-amber-900/40   text-amber-300   border-amber-700',
  high:     'bg-orange-900/40  text-orange-300  border-orange-700',
  critical: 'bg-red-900/40     text-red-300     border-red-700',
}

export default function RiskBadge({
  level,
  className = '',
}: {
  level: RiskLevel
  className?: string
}) {
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border uppercase tracking-wide ${styles[level]} ${className}`}>
      {level}
    </span>
  )
}
