export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type Severity = 'low' | 'medium' | 'high'

export interface HeaderFinding {
  header: string
  status: 'present' | 'missing' | 'weak'
  severity: Severity
  value: string | null
  description: string
  remediation: string
}

export interface InformationLeakFinding {
  header: string
  value: string
  severity: Severity
  description: string
  remediation: string
}

export interface HeaderScanResult {
  domain: string
  scanned_url: string
  scan_timestamp: string
  findings: HeaderFinding[]
  information_leaks: InformationLeakFinding[]
  risk_score: number
  risk_level: RiskLevel
  summary: Record<string, number>
}

export interface DNSRecord {
  record_type: string
  values: string[]
}

export interface DNSFinding {
  check: string
  status: 'pass' | 'fail' | 'warn' | 'info'
  severity: Severity | null
  description: string
  remediation: string | null
}

export interface DNSScanResult {
  domain: string
  scan_timestamp: string
  records: DNSRecord[]
  findings: DNSFinding[]
  risk_score: number
  risk_level: RiskLevel
  summary: Record<string, number>
}

export interface ExposureFinding {
  path: string
  label: string
  status_code: number
  exposed: boolean
  severity: Severity | 'info'
  description: string
  remediation: string | null
}

export interface ExposureScanResult {
  domain: string
  scan_timestamp: string
  findings: ExposureFinding[]
  risk_score: number
  risk_level: RiskLevel
  summary: Record<string, number>
}

export interface FingerprintMatch {
  name: string
  category: 'cms' | 'framework' | 'cdn' | 'server' | 'library'
  confidence: 'low' | 'medium' | 'high'
  evidence: string
}

export interface FingerprintScanResult {
  domain: string
  scan_timestamp: string
  matches: FingerprintMatch[]
  summary: Record<string, unknown>
}

export interface CertInfo {
  subject: string
  issuer: string
  not_before: string
  not_after: string
  days_until_expiry: number
  is_self_signed: boolean
  sans: string[]
  serial_number: string
}

export interface TLSVersionCheck {
  version: string
  supported: boolean | null
}

export interface SSLFinding {
  check: string
  status: 'pass' | 'fail' | 'warn' | 'info'
  severity: Severity | null
  description: string
  remediation: string | null
}

export interface SSLScanResult {
  domain: string
  port: number
  scan_timestamp: string
  certificate: CertInfo | null
  tls_versions: TLSVersionCheck[]
  findings: SSLFinding[]
  risk_score: number
  risk_level: RiskLevel
  summary: Record<string, unknown>
}

export interface TopFinding {
  scanner: string
  severity: Severity
  title: string
  description: string
  remediation: string | null
}

export interface FullScanResult {
  scan_id: string | null
  domain: string
  scan_timestamp: string
  headers: HeaderScanResult
  dns: DNSScanResult
  ssl: SSLScanResult
  exposure: ExposureScanResult
  fingerprint: FingerprintScanResult
  overall_risk_score: number
  overall_risk_level: RiskLevel
  top_findings: TopFinding[]
}

export interface ScanHistoryItem {
  scan_id: string
  domain: string
  scan_timestamp: string
  overall_risk_score: number
  overall_risk_level: RiskLevel
}
