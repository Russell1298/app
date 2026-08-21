import { getScan } from '@/lib/api'
import ScanReport from '@/components/ScanReport'

export default async function ReportPage({ params }: { params: { scanId: string } }) {
  let result = null
  let error = null

  try {
    result = await getScan(params.scanId)
  } catch (e) {
    error = e instanceof Error ? e.message : 'Failed to load report'
  }

  if (error || !result) {
    return (
      <div className="text-center py-20">
        <p className="text-red-400 text-lg mb-4">{error ?? 'Report not found'}</p>
        <a href="/" className="text-cyan-400 hover:underline">← Run a new scan</a>
      </div>
    )
  }

  return <ScanReport result={result} />
}
