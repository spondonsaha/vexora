import type {
  CreateScopeTargetInput,
  EndpointList,
  HealthStatus,
  JSFindingList,
  LiveWebServerList,
  NetworkServiceList,
  NucleiFindingList,
  OpenRedirectFindingList,
  ScanJob,
  ScanJobList,
  ScopeTarget,
  ScopeTargetList,
  ScopeTargetType,
  SQLiFindingList,
  SubdomainList,
  Workflow,
  WorkflowList,
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'

export const liveServerScreenshotUrl = (id: string) =>
  `${API_BASE}/live-servers/${id}/screenshot`

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  })

  if (res.status === 204) {
    return undefined as T
  }

  const text = await res.text()
  let body: unknown
  try {
    body = text ? JSON.parse(text) : undefined
  } catch {
    body = undefined
  }

  if (!res.ok) {
    const env = body as ErrorEnvelope | undefined
    throw new ApiError(
      res.status,
      env?.error?.code ?? 'request_failed',
      env?.error?.message ?? res.statusText,
    )
  }

  return body as T
}

export const api = {
  health: () => request<HealthStatus>('/health'),

  listScopeTargets: (type?: ScopeTargetType) =>
    request<ScopeTargetList>(`/scope-targets${type ? `?type=${type}` : ''}`),

  getScopeTarget: (id: string) => request<ScopeTarget>(`/scope-targets/${id}`),

  createScopeTarget: (input: CreateScopeTargetInput) =>
    request<ScopeTarget>('/scope-targets', {
      method: 'POST',
      body: JSON.stringify(input),
    }),

  activateScopeTarget: (id: string, authConfirmed?: boolean) =>
    request<ScopeTarget>(`/scope-targets/${id}/activate`, {
      method: 'PATCH',
      body: JSON.stringify(authConfirmed === undefined ? {} : { auth_confirmed: authConfirmed }),
    }),

  setScopeTargetNotes: (id: string, notes: string) =>
    request<ScopeTarget>(`/scope-targets/${id}/notes`, {
      method: 'PATCH',
      body: JSON.stringify({ notes }),
    }),

  deleteScopeTarget: (id: string) =>
    request<void>(`/scope-targets/${id}`, { method: 'DELETE' }),

  runScan: (tool: string, scopeTargetId: string, options?: Record<string, unknown>) =>
    request<ScanJob>(`/scans/${tool}`, {
      method: 'POST',
      body: JSON.stringify(
        options === undefined
          ? { scope_target_id: scopeTargetId }
          : { scope_target_id: scopeTargetId, options },
      ),
    }),

  listScans: (scopeTargetId: string) =>
    request<ScanJobList>(`/scans?scope_target_id=${scopeTargetId}`),

  getScan: (id: string) => request<ScanJob>(`/scans/${id}`),

  getScanRawOutput: async (id: string, stream: 'stdout' | 'stderr' = 'stdout') => {
    const res = await fetch(`${API_BASE}/scans/${id}/raw-output?stream=${stream}`)
    if (!res.ok) {
      throw new ApiError(res.status, 'raw_output_unavailable', 'raw output is not available yet')
    }
    return res.text()
  },

  listSubdomains: (scopeTargetId: string) =>
    request<SubdomainList>(`/targets/${scopeTargetId}/subdomains`),

  listLiveServers: (scopeTargetId: string) =>
    request<LiveWebServerList>(`/targets/${scopeTargetId}/live-servers`),

  listEndpoints: (scopeTargetId: string) =>
    request<EndpointList>(`/targets/${scopeTargetId}/endpoints`),

  listNucleiFindings: (scopeTargetId: string) =>
    request<NucleiFindingList>(`/targets/${scopeTargetId}/nuclei-findings`),

  listNetworkServices: (scopeTargetId: string) =>
    request<NetworkServiceList>(`/targets/${scopeTargetId}/network-services`),

  listSQLiFindings: (scopeTargetId: string) =>
    request<SQLiFindingList>(`/targets/${scopeTargetId}/sqli-findings`),

  listJSFindings: (scopeTargetId: string) =>
    request<JSFindingList>(`/targets/${scopeTargetId}/js-findings`),

  listOpenRedirectFindings: (scopeTargetId: string) =>
    request<OpenRedirectFindingList>(`/targets/${scopeTargetId}/open-redirect-findings`),

  runWildcardWorkflow: (scopeTargetId: string) =>
    request<Workflow>('/workflows/wildcard/run', {
      method: 'POST',
      body: JSON.stringify({ scope_target_id: scopeTargetId }),
    }),

  runDomainWorkflow: (scopeTargetId: string) =>
    request<Workflow>('/workflows/domain/run', {
      method: 'POST',
      body: JSON.stringify({ scope_target_id: scopeTargetId }),
    }),

  listWorkflows: (scopeTargetId: string) =>
    request<WorkflowList>(`/workflows?scope_target_id=${scopeTargetId}`),

  getWorkflow: (id: string) => request<Workflow>(`/workflows/${id}`),
}
