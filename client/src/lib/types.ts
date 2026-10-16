export type ScopeTargetType = 'company' | 'wildcard' | 'url'

export interface ScopeTarget {
  id: string
  type: ScopeTargetType
  value: string
  description: string
  notes: string
  auth_confirmed: boolean
  active: boolean
  created_at: string
  updated_at: string
}

export interface ScopeTargetList {
  items: ScopeTarget[]
  count: number
}

export interface CreateScopeTargetInput {
  type: ScopeTargetType
  value: string
  description?: string
  auth_confirmed: boolean
}

export interface HealthStatus {
  status: string
  database: string
  time: string
}

export type ScanJobStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled'

export interface ScanJob {
  id: string
  scope_target_id: string
  workflow_id: string | null
  workflow_step_id: string | null
  tool: string
  status: ScanJobStatus
  options: unknown
  started_at: string | null
  finished_at: string | null
  stdout_path: string | null
  stderr_path: string | null
  exit_code: number | null
  created_at: string
}

export interface ScanJobList {
  items: ScanJob[]
  count: number
}

export type TakeoverStatus = 'vulnerable' | 'dangling' | 'edge' | 'safe' | 'unknown'

export interface Subdomain {
  id: string
  wildcard_target_id: string
  subdomain: string
  source_tool: string
  cname: string | null
  cname_chain: string[]
  a_records: string[]
  reverse_dns: string[]
  takeover_status: TakeoverStatus | null
  takeover_service: string | null
  takeover_detail: string | null
  dns_checked_at: string | null
  first_seen: string
  last_seen: string
}

export interface SubdomainList {
  items: Subdomain[]
  count: number
}

export type WorkflowType = 'company' | 'wildcard' | 'url' | 'domain'
export type WorkflowStatus = 'queued' | 'running' | 'done' | 'failed' | 'cancelled'
export type StepStatus = WorkflowStatus

export type AuditStatus = 'pass' | 'warn' | 'fail' | 'info'

export interface AuditCheck {
  id: string
  title: string
  status: AuditStatus
  detail: string
}

export interface AuditSummary {
  section?: string
  title?: string
  domain?: string
  score?: number
  checks?: AuditCheck[]
  error?: string
}

export interface WorkflowStep {
  id: string
  workflow_id: string
  step_number: number
  step_key: string
  title: string
  description: string | null
  status: StepStatus
  summary: Record<string, unknown>
  started_at: string | null
  finished_at: string | null
  created_at: string
  jobs?: ScanJob[]
}

export interface Workflow {
  id: string
  scope_target_id: string
  workflow_type: WorkflowType
  status: WorkflowStatus
  current_step: number
  error: string | null
  created_at: string
  updated_at: string
  finished_at: string | null
  steps?: WorkflowStep[]
}

export interface WorkflowList {
  items: Workflow[]
  count: number
}

export interface LiveWebServer {
  id: string
  subdomain_id: string | null
  ip: string | null
  url: string
  status_code: number | null
  title: string | null
  content_length: number | null
  tech_stack: string[]
  headers: Record<string, unknown>
  tls: Record<string, unknown>
  screenshot_path: string | null
  created_at: string
  updated_at: string
}

export interface LiveWebServerList {
  items: LiveWebServer[]
  count: number
}

export interface Endpoint {
  id: string
  live_web_server_id: string | null
  wildcard_target_id: string | null
  host: string | null
  url: string | null
  path: string
  status_code: number | null
  content_length: number | null
  source_tool: string | null
  interesting: boolean
  created_at: string
}

export interface EndpointList {
  items: Endpoint[]
  count: number
}

export type NucleiCategory = 'xss' | 'cve' | 'takeover' | 'misconfig' | 'all'

export type NucleiSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

export interface NucleiFinding {
  id: number
  scope_target_id: string
  scan_job_id: string | null
  category: string
  template_id: string
  name: string
  severity: NucleiSeverity
  type: string | null
  host: string | null
  matched_at: string
  description: string | null
  reference: string[]
  tags: string[]
  extracted: string[]
  cvss_score: number | null
  curl_command: string | null
  created_at: string
  updated_at: string
}

export interface NucleiFindingList {
  items: NucleiFinding[]
  count: number
}

export type PortProfile = 'top100' | 'top1000' | 'full'

export interface NetworkService {
  id: number
  scope_target_id: string
  scan_job_id: string | null
  ip: string
  port: number
  protocol: string
  state: string
  tls: boolean
  service: string | null
  product: string | null
  version: string | null
  banner: string | null
  hosts: string[]
  created_at: string
  updated_at: string
}

export interface NetworkServiceList {
  items: NetworkService[]
  count: number
}

export type SQLiTechnique = 'B' | 'E' | 'U' | 'S' | 'T' | 'Q'

export interface SQLiFinding {
  id: number
  scope_target_id: string
  scan_job_id: string | null
  url: string
  parameter: string
  method: string
  technique: string
  title: string
  payload: string
  dbms: string
  created_at: string
  updated_at: string
}

export interface SQLiFindingList {
  items: SQLiFinding[]
  count: number
}

export type JSFindingType =
  | 'url'
  | 'api_endpoint'
  | 'credential'
  | 'aws_key'
  | 'google_api_key'
  | 'google_oauth'
  | 'github_token'
  | 'slack_token'
  | 'stripe_key'
  | 'twilio_key'
  | 'sendgrid_key'
  | 'mailgun_key'
  | 'private_key'
  | 'jwt'
  | 'firebase'
  | 's3_bucket'
  | 'internal_ip'
  | 'email'
  | 'subdomain'
  | 'graphql'
  | 'admin_route'
  | 'js_variable'

export interface JSFinding {
  id: number
  scope_target_id: string
  scan_job_id: string | null
  js_url: string
  host: string
  finding_type: string
  value: string
  context: string
  created_at: string
  updated_at: string
}

export interface JSFindingList {
  items: JSFinding[]
  count: number
}

export type OpenRedirectFindingType =
  | 'open_redirect'
  | 'dom_redirect'
  | 'header_injection'
  | 'javascript_uri'
  | 'reflection'
  | 'redirect_external'

export interface OpenRedirectFinding {
  id: number
  scope_target_id: string
  scan_job_id: string | null
  url: string
  parameter: string
  payload: string
  finding_type: string
  status_code: number | null
  location: string
  evidence: string
  created_at: string
  updated_at: string
}

export interface OpenRedirectFindingList {
  items: OpenRedirectFinding[]
  count: number
}

export type SSRFFindingType = 'candidate' | 'ssrf_oob' | 'metadata_read'

export interface SSRFFinding {
  id: number
  scope_target_id: string
  scan_job_id: string | null
  url: string
  parameter: string
  payload: string
  method: string
  finding_type: string
  severity: string
  confirmed: boolean
  protocol: string
  remote_address: string
  evidence: string
  created_at: string
  updated_at: string
}

export interface SSRFFindingList {
  items: SSRFFinding[]
  count: number
}

export type TechnologyCategory =
  | 'cms'
  | 'framework'
  | 'server'
  | 'js-library'
  | 'analytics'
  | 'cdn'
  | 'waf'
  | 'language'
  | 'database'
  | 'wordpress-theme'
  | 'wordpress-plugin'
  | 'other'

export interface Technology {
  id: number
  scope_target_id: string
  live_web_server_id: string
  scan_job_id: string | null
  name: string
  version: string
  category: string
  detected_by: string
  cve_refs: string[]
  created_at: string
  updated_at: string
}

export interface TechnologyList {
  items: Technology[]
  count: number
}

export interface WhoisRecord {
  id: number
  scope_target_id: string
  root_domain_id: string | null
  scan_job_id: string | null
  domain: string
  registrant_org: string
  registrar: string
  registered_at: string | null
  expires_at: string | null
  nameservers: string[]
  statuses: string[]
  source: string
  created_at: string
  updated_at: string
}

export interface WhoisRecordList {
  items: WhoisRecord[]
  count: number
}

export const scopeTargetTypeLabels: Record<ScopeTargetType, string> = {
  company: 'Company',
  wildcard: 'Wildcard',
  url: 'URL',
}
