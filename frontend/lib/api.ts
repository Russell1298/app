import type { FullScanResult, ScanHistoryItem } from '@/types/scan'

const BASE = '/api/v1'

const NGROK_HEADERS = { 'ngrok-skip-browser-warning': 'true' }

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { ...NGROK_HEADERS, ...options?.headers },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail ?? `HTTP ${res.status}`)
  }
  return res.json()
}

export async function runFullScan(domain: string): Promise<FullScanResult> {
  return request<FullScanResult>('/scan/full', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  })
}

export async function getScan(scanId: string): Promise<FullScanResult> {
  return request<FullScanResult>(`/scans/${scanId}`)
}

export async function listScans(domain?: string, limit = 20): Promise<ScanHistoryItem[]> {
  const params = new URLSearchParams({ limit: String(limit) })
  if (domain) params.set('domain', domain)
  return request<ScanHistoryItem[]>(`/scans?${params}`)
}
