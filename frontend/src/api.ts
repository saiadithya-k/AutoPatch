import type { Audit, Context, Finding, Page, Patch, Report, Retry, Risk, Validation, Workflow } from './types';

const base = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
async function request<T>(path: string, signal?: AbortSignal, body?: unknown): Promise<T> {
  const response = await fetch(`${base}${path}`, {
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000),
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data?.detail;
    throw new ApiError(response.status, typeof detail === 'string' ? detail : detail ? JSON.stringify(detail) : `Request failed (${response.status}). Check that the backend is running.`);
  }
  return data as T;
}
const id = encodeURIComponent;
export const api = {
  workflows: (offset: number, signal?: AbortSignal) => request<Page<Workflow>>(`/api/workflows?limit=20&offset=${offset}`, signal),
  workflow: (workflowId: string, signal?: AbortSignal) => request<Workflow>(`/api/workflows/${id(workflowId)}`, signal),
  create: (repository_path: string, max_retries: number) => request<{ id?: string; workflow_id?: string; status: string }>('/api/workflows', undefined, { repository_path, max_retries }),
  findings: (workflowId: string, signal?: AbortSignal) => request<Finding[]>(`/api/vulnerabilities?workflow_id=${id(workflowId)}`, signal),
  patches: (findingId: string, signal?: AbortSignal) => request<Patch[]>(`/api/vulnerabilities/${id(findingId)}/patches`, signal),
  validation: (patchId: string, signal?: AbortSignal) => request<Validation>(`/api/patches/${id(patchId)}/validation`, signal),
  retries: (patchId: string, signal?: AbortSignal) => request<Retry[]>(`/api/patches/${id(patchId)}/retry-history`, signal),
  risk: (findingId: string, signal?: AbortSignal) => request<Risk>(`/api/vulnerabilities/${id(findingId)}/risk`, signal),
  context: (findingId: string, signal?: AbortSignal) => request<Context>(`/api/vulnerabilities/${id(findingId)}/context`, signal),
  audit: (workflowId: string, signal?: AbortSignal) => request<Audit[]>(`/api/workflows/${id(workflowId)}/audit`, signal),
  report: (workflowId: string, signal?: AbortSignal) => request<Report>(`/api/reports/${id(workflowId)}`, signal),
  review: (patchId: string, decision: 'approve' | 'reject', body: { reviewer_label: string; comment: string }) => request<Record<string, unknown>>(`/api/patches/${id(patchId)}/${decision}`, undefined, body),
};
export function errorText(error: unknown): string { return error instanceof Error ? error.message : 'Unable to load this information.'; }
export function download(name: string, content: string, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
