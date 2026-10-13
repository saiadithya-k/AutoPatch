import { useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { api, download, errorText } from './api';
import type { Finding, Patch, Validation, Workflow } from './types';

const terminal = new Set(['READY_FOR_REVIEW', 'COMPLETED', 'FAILED', 'CANCELLED', 'APPROVED', 'REJECTED']);
const readable = (value: string) => value.toLowerCase().replaceAll('_', ' ');
function date(value?: string | null) {
  if (!value) return '—';
  const utcValue = /(?:Z|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  return new Date(utcValue).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
function useRemote<T>(key: string | null, loader: (signal: AbortSignal) => Promise<T>, poll?: (data: T) => boolean) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [revision, setRevision] = useState(0);
  const loaderRef = useRef(loader); loaderRef.current = loader;
  const pollRef = useRef(poll); pollRef.current = poll;
  useEffect(() => {
    setData(undefined); setError(undefined);
    if (!key) { setLoading(false); return; }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    const load = async () => {
      setLoading(true);
      try {
        const next = await loaderRef.current(controller.signal);
        if (controller.signal.aborted) return;
        setData(next); setError(undefined); failures = 0;
        if (pollRef.current?.(next)) timer = setTimeout(load, 3000);
      } catch (e) {
        if (controller.signal.aborted) return;
        setError(errorText(e));
        if (pollRef.current && ++failures < 3) timer = setTimeout(load, 5000);
      } finally { if (!controller.signal.aborted) setLoading(false); }
    };
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [key, revision]);
  return { data, error, loading, refresh: () => setRevision(value => value + 1) };
}
function Badge({ value }: { value: string }) {
  return <span className={`badge ${value.toLowerCase()}`}>{readable(value)}</span>;
}
function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) {
  return <div role={error ? 'alert' : 'status'} className={`notice ${error ? 'error' : ''}`}>{children}</div>;
}
function Empty({ children }: { children: ReactNode }) { return <div className="empty">{children}</div>; }
function EvidenceErrors({ errors }: { errors?: unknown }) {
  return Array.isArray(errors) && errors.length > 0 ? <Notice error>Some stored evidence could not be read. Inspect the complete report and repeat validation before approval.<details><summary>Evidence diagnostics</summary><pre>{JSON.stringify(errors, null, 2)}</pre></details></Notice> : null;
}
function Check({ label, pass }: { label: string; pass: boolean }) {
  return <div className="check"><span className={pass ? 'pass' : 'fail'}>{pass ? '✓' : '×'}</span>{label}<strong>{pass ? 'Passed' : 'Not confirmed'}</strong></div>;
}

export default function App() {
  const [selected, setSelected] = useState(() => new URLSearchParams(location.search).get('workflow') || '');
  const [offset, setOffset] = useState(0);
  const [path, setPath] = useState('');
  const [retries, setRetries] = useState(3);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const [revision, setRevision] = useState(0);
  const runs = useRemote(`runs:${offset}:${revision}`, signal => api.workflows(offset, signal));
  const workflow = useRemote(selected ? `${selected}:${revision}` : null, signal => api.workflow(selected, signal), data => !terminal.has(data.status));
  const [tab, setTab] = useState<'findings' | 'activity' | 'report'>('findings');
  const select = (workflowId: string) => {
    setSelected(workflowId); setTab('findings');
    const url = new URL(location.href);
    url.searchParams.set('workflow', workflowId); history.replaceState(null, '', url);
  };
  const refresh = () => setRevision(value => value + 1);
  useEffect(() => { if (workflow.data && terminal.has(workflow.data.status)) runs.refresh(); }, [workflow.data?.status]);
  async function submit(event: FormEvent) {
    event.preventDefault(); setSubmitting(true); setSubmitError('');
    try {
      const created = await api.create(path.trim(), retries);
      const workflowId = created.id || created.workflow_id;
      if (!workflowId) throw new Error('The server did not return a workflow identifier.');
      select(workflowId); refresh();
    } catch (e) { setSubmitError(errorText(e)); } finally { setSubmitting(false); }
  }
  return <div className="app">
    <aside className="sidebar">
      <a className="brand" href="/" aria-label="AutoPatch home"><span className="brand-icon">A</span><span>AutoPatch<small>Remediation workspace</small></span></a>
      <div className="sidebar-heading"><span>WORKFLOWS</span><button className="icon-button" onClick={runs.refresh} aria-label="Refresh workflow list">↻</button></div>
      {runs.error && <Notice error>{runs.error}</Notice>}
      {!runs.data && runs.loading && <Notice>Loading workflows…</Notice>}
      {runs.data?.items.length === 0 && <p className="muted">Your first workflow will appear here.</p>}
      <nav className="run-list" aria-label="Workflow history">{runs.data?.items.map(run => <button key={run.id} className={`run ${run.id === selected ? 'selected' : ''}`} onClick={() => select(run.id)}><span className="run-name">{run.repository_path.split(/[\\/]/).filter(Boolean).at(-1)}</span><Badge value={run.status} /><small>{date(run.created_at)}</small></button>)}</nav>
      {runs.data && runs.data.total > 20 && <div className="pagination"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))}>Previous</button><button disabled={offset + 20 >= runs.data.total} onClick={() => setOffset(offset + 20)}>Next</button></div>}
      <div className="sidebar-foot"><span className="status-dot" />Local workspace<p>Candidate patches require your review.</p></div>
    </aside>
    <main>
      <header className="topbar"><span>SECURITY OPERATIONS / WORKFLOWS</span><span className="local-label">Developer workspace</span></header>
      <section className="page-title"><div><p className="eyebrow">FIND. VALIDATE. REVIEW.</p><h1>Remediation, with evidence.</h1><p>Scan a Python repository and review tested patch proposals.</p></div><span className="title-mark">↗</span></section>
      <section className="panel submit-panel"><div><h2>Start a workflow</h2><p className="muted">Use an absolute repository path accessible to the backend.</p></div><form onSubmit={submit}><label className="path-label">Repository path<input required value={path} onChange={e => setPath(e.target.value)} placeholder="D:\projects\your-repository" disabled={submitting} /></label><label className="retry-label">Additional retries<input type="number" min="0" max="10" value={retries} onChange={e => setRetries(Number(e.target.value))} disabled={submitting} /></label><button className="primary" type="submit" disabled={submitting || !path.trim()}>{submitting ? 'Starting…' : 'Start workflow →'}</button></form>{submitError && <Notice error>{submitError}</Notice>}</section>
      {workflow.error && <Notice error>{workflow.error} <button onClick={workflow.refresh}>Try again</button></Notice>}
      {!selected && <Empty>Select a workflow from the history, or submit a repository to begin.</Empty>}
      {selected && !workflow.data && workflow.loading && <Notice>Loading workflow…</Notice>}
      {workflow.data && <>
        <WorkflowOverview workflow={workflow.data} refresh={refresh} />
        <div className="tabs" role="tablist" aria-label="Workflow details">{(['findings', 'activity', 'report'] as const).map(value => <button key={value} role="tab" aria-selected={tab === value} onClick={() => setTab(value)}>{value === 'findings' ? 'Findings & patches' : value === 'activity' ? 'Activity log' : 'Report'}</button>)}</div>
        {tab === 'findings' && <Findings workflow={workflow.data} revision={revision} onReview={refresh} />}
        {tab === 'activity' && <Activity workflow={workflow.data} revision={revision} />}
        {tab === 'report' && <ReportView workflow={workflow.data} revision={revision} />}
      </>}
      <footer>AutoPatch · Approval records your decision. Source files remain unchanged.</footer>
    </main>
  </div>;
}

function WorkflowOverview({ workflow: w, refresh }: { workflow: Workflow; refresh: () => void }) {
  const active = !terminal.has(w.status);
  return <section className="workflow-overview"><div className="workflow-heading"><div><div className="heading-row"><h2>Workflow overview</h2><Badge value={w.status} /></div><p className="repository-path">{w.repository_path}</p><small className="muted">{w.id} · Started {date(w.started_at || w.created_at)}</small></div><button onClick={refresh}>Refresh</button></div><div className="metrics"><div><span>Current stage</span><strong className={active ? 'active-stage' : ''}>{readable(w.current_stage || w.status)}</strong></div><div><span>Findings</span><strong>{w.total_findings ?? '—'}</strong></div><div><span>Processed</span><strong>{w.processed_findings ?? '—'}</strong></div><div><span>Ready for review</span><strong>{w.reviewable_count ?? '—'}</strong></div><div><span>Failed findings</span><strong>{w.failed_count ?? '—'}</strong></div></div><EvidenceErrors errors={w.evidence_errors} />{w.outcome && <p className="muted">Outcome: {readable(w.outcome)}</p>}{w.error_message && <Notice error>{w.errors?.length ? `${w.errors.length} findings encountered errors. See finding errors for details.` : w.error_message}</Notice>}{w.errors?.length ? <details><summary>Finding errors · {w.errors.length}</summary>{w.errors.map((error, i) => <Notice error key={i}>{error}</Notice>)}</details> : null}{active && <Notice>Workflow running · progress updates every 3 seconds.</Notice>}</section>;
}
function Findings({ workflow, revision, onReview }: { workflow: Workflow; revision: number; onReview: () => void }) {
  const result = useRemote(`${workflow.id}:${revision}`, signal => api.findings(workflow.id, signal), () => !terminal.has(workflow.status));
  const [selected, setSelected] = useState('');
  const findings = [...(result.data || [])].sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1));
  const finding = findings.find(f => f.id === selected) || findings[0];
  return <div className="findings-layout"><section className="panel finding-list"><div className="section-heading"><h2>Findings</h2><span className="count">{findings.length}</span></div>{result.error && <Notice error>{result.error} <button onClick={result.refresh}>Retry</button></Notice>}{result.loading && !result.data && <Notice>Loading findings…</Notice>}{result.data && !findings.length && <Empty>{terminal.has(workflow.status) ? 'No findings recorded. Check the activity log for the scan outcome.' : 'Findings will appear as scanning completes.'}</Empty>}{findings.map(f => <button className={`finding ${f.id === finding?.id ? 'selected' : ''}`} key={f.id} onClick={() => setSelected(f.id)}><div><Badge value={f.severity} /><span className="score">{f.risk_score == null ? 'Unscored' : `${f.risk_score.toFixed(1)} risk`}</span></div><strong>{f.type}</strong><small>{f.file_path}:{f.line_start ?? '?'}</small><small className="finding-status">{readable(f.status)}</small></button>)}</section>{finding ? <FindingDetail finding={finding} workflow={workflow} revision={revision} onReview={onReview} /> : <section className="panel"><Empty>Select a finding to inspect remediation evidence.</Empty></section>}</div>;
}
function FindingDetail({ finding, workflow, revision, onReview }: { finding: Finding; workflow: Workflow; revision: number; onReview: () => void }) {
  const risk = useRemote(finding.id, signal => api.risk(finding.id, signal));
  const context = useRemote(finding.id, signal => api.context(finding.id, signal));
  const patches = useRemote(`${finding.id}:${revision}`, signal => api.patches(finding.id, signal), () => !terminal.has(workflow.status));
  const [selectedPatch, setSelectedPatch] = useState('');
  const sorted = [...(patches.data || [])].sort((a, b) => b.attempt_number - a.attempt_number);
  const patch = sorted.find(p => p.id === selectedPatch) || sorted[0];
  return <div className="detail-stack"><section className="panel"><div className="heading-row"><h2>{finding.type}</h2><Badge value={finding.severity} /></div><p>{finding.description}</p><p className="muted">{finding.tool} · {finding.rule_id || finding.cwe || 'Security finding'} · {finding.file_path}:{finding.line_start ?? '?'}</p><div className="risk-note"><strong>{risk.data ? `${risk.data.risk_score.toFixed(1)} / 10 · ${readable(risk.data.priority)}` : 'Risk assessment'}</strong><p>{risk.data?.reasoning || finding.risk_reasoning || risk.error || 'Assessment pending.'}</p></div><details><summary>Repository context</summary>{context.loading && <Notice>Loading context…</Notice>}{context.error && <Notice error>{context.error}</Notice>}{context.data && <><p className="muted">Source window begins at line {context.data.context_window_start}{context.data.enclosing_scope ? ` · ${context.data.enclosing_scope.name}` : ''}</p><pre>{context.data.surrounding_code}</pre><p className="muted">Related tests: {context.data.related_tests.map(t => t.file_path).join(', ') || 'None identified'}</p>{context.data.warnings.map((warning, i) => <Notice key={i}>{warning}</Notice>)}</>}</details></section><section className="panel"><div className="section-heading"><h2>Patch review</h2>{patch && <select aria-label="Patch attempt" value={patch.id} onChange={e => setSelectedPatch(e.target.value)}>{sorted.map(p => <option key={p.id} value={p.id}>Attempt {p.attempt_number} · {readable(p.status)}</option>)}</select>}</div>{patches.error && <Notice error>{patches.error}</Notice>}{patches.loading && !patches.data && <Notice>Loading patch proposals…</Notice>}{patches.data && !patch && <Empty>{terminal.has(workflow.status) ? 'No candidate patch was generated for this finding.' : 'A candidate will appear after generation.'}</Empty>}{patch && <PatchReview key={patch.id} patch={patch} latest={patch.id === sorted[0]?.id} workflowComplete={Boolean(workflow.completed_at)} onReview={onReview} revision={revision} />}</section></div>;
}
function PatchReview({ patch, latest, workflowComplete, onReview, revision }: { patch: Patch; latest: boolean; workflowComplete: boolean; onReview: () => void; revision: number }) {
  const validation = useRemote(patch.status === 'FAILED' ? null : `${patch.id}:${patch.status}:${revision}`, signal => api.validation(patch.id, signal), () => patch.status === 'VALIDATING' || patch.status === 'GENERATED');
  const retries = useRemote(`${patch.id}:${patch.status}:${revision}`, signal => api.retries(patch.id, signal));
  const [reviewer, setReviewer] = useState('');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const v = validation.data;
  const eligible = workflowComplete && latest && patch.status === 'READY_FOR_REVIEW' && v?.status === 'PASSED' && v.patch_applied && v.syntax_check_passed && v.tests_passed && v.security_scan_passed && v.scanner_metadata?.coverage_complete === true && v.original_vulnerability_resolved && !v.regression_detected && v.new_findings_count === 0;
  async function review(decision: 'approve' | 'reject') {
    setBusy(true); setError(''); setMessage('');
    try { await api.review(patch.id, decision, { reviewer_label: reviewer.trim(), comment: comment.trim() }); setMessage(`Patch ${decision === 'approve' ? 'approved' : 'rejected'}. Your decision has been saved.`); onReview(); }
    catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  return <><EvidenceErrors errors={patch.evidence_errors} /><div className="patch-meta"><Badge value={patch.status} /><small>{patch.id}</small><button disabled={!patch.patch_content} onClick={() => download(`${patch.id}.patch`, patch.patch_content)}>Download patch ↓</button></div><p>{patch.explanation || 'No explanation was recorded.'}</p><p className="muted">Changed files: {patch.files_changed.join(', ') || 'None recorded'}</p><div className="diff" aria-label="Candidate unified diff"><pre>{(patch.patch_content || 'No candidate diff was generated.').split('\n').map((line, i) => <span key={i} className={line.startsWith('+++') || line.startsWith('---') ? 'diff-file' : line.startsWith('+') ? 'diff-add' : line.startsWith('-') ? 'diff-remove' : line.startsWith('@@') ? 'diff-hunk' : ''}>{line || ' '}{'\n'}</span>)}</pre></div><h3>Validation evidence</h3>{patch.status === 'FAILED' && <Notice>Validation was not run because candidate generation failed.</Notice>}{validation.loading && !v && <Notice>Loading validation…</Notice>}{validation.error && <Notice error>{validation.error} <button onClick={validation.refresh}>Refresh evidence</button></Notice>}{v && <Evidence validation={v} />}<details><summary>Retry history · {retries.data?.length ?? '—'} attempts</summary>{retries.error && <Notice error>{retries.error}</Notice>}{retries.data?.map(r => <div className="retry" key={r.patch_id}><div className="heading-row"><strong>Attempt {r.attempt_number}</strong><Badge value={r.status} /></div><small>{r.patch_id}</small>{r.failure_reason && <p>{r.failure_reason}</p>}{r.failure_category && <small>{readable(r.failure_category)}</small>}</div>)}</details><div className="review-box"><h3>Your review</h3><p className="muted">Review the exact candidate and evidence before recording a decision.</p>{!eligible && <p className="muted">{!workflowComplete ? 'Wait until the workflow finishes before reviewing proposals.' : !latest ? 'This attempt has been superseded.' : patch.status === 'APPROVED' || patch.status === 'REJECTED' ? `This proposal has been ${readable(patch.status)}.` : 'Review becomes available after complete, successful validation.'}</p>}<label>Reviewer label<input value={reviewer} onChange={e => setReviewer(e.target.value)} disabled={!eligible || busy} placeholder="Your name" /></label><label>Review comment<textarea value={comment} onChange={e => setComment(e.target.value)} disabled={!eligible || busy} placeholder="Required when rejecting a proposal" rows={3} /></label><div className="review-actions"><button className="primary" disabled={!eligible || busy || !reviewer.trim()} onClick={() => void review('approve')}>{busy ? 'Saving…' : 'Approve proposal'}</button><button className="danger" disabled={!eligible || busy || !reviewer.trim() || !comment.trim()} onClick={() => void review('reject')}>Reject proposal</button></div>{error && <Notice error>{error}</Notice>}{message && <Notice>{message}</Notice>}</div></>;
}
function Evidence({ validation: v }: { validation: Validation }) {
  return <><div className="evidence-heading"><Badge value={v.status} /><span>{v.duration.toFixed(2)}s · {v.tests_run ?? 0} tests</span></div><Notice>{v.sandbox_type.toLowerCase().includes('docker') ? 'Validated in a Docker sandbox.' : `Development execution mode: ${readable(v.sandbox_type)}.`}</Notice>{v.status !== 'PASSED' && <Notice error>{v.failure_reason || 'Validation has not confirmed this proposal.'}{v.failure_category ? ` (${readable(v.failure_category)})` : ''}</Notice>}{v.scanner_metadata?.coverage_complete !== true && <Notice error>Scanner coverage is incomplete or unavailable. Remediation cannot be confirmed.</Notice>}<div className="checks"><Check label="Patch application" pass={v.patch_applied} /><Check label="Compilation" pass={v.syntax_check_passed} /><Check label="Tests" pass={v.tests_passed} /><Check label="Security re-scan" pass={v.security_scan_passed} /><Check label="Required scanner coverage" pass={v.scanner_metadata?.coverage_complete === true} /><Check label="Original finding resolved" pass={v.original_vulnerability_resolved} /><Check label="No new findings or regressions" pass={!v.regression_detected && v.new_findings_count === 0 && v.status === 'PASSED'} /></div><details><summary>Scanner coverage & provenance</summary><p className="muted">Required scanners: {v.scanner_metadata?.required_scanners?.join(', ') || 'Unavailable'} · Scan: {v.scanner_metadata?.scan_status ? readable(v.scanner_metadata.scan_status) : 'Unavailable'}</p><pre>{v.scanner_metadata ? JSON.stringify(v.scanner_metadata, null, 2) : 'Scanner metadata was not recorded.'}</pre></details><details><summary>Test output & scanner logs</summary><p className="muted">Test exit code: {v.test_exit_code ?? 'Unavailable'} · New findings: {v.new_findings_count}</p><pre>{[v.test_stdout, v.test_stderr, v.validation_logs].filter(Boolean).join('\n\n') || 'No execution logs were recorded.'}</pre></details></>;
}
function Activity({ workflow, revision }: { workflow: Workflow; revision: number }) {
  const result = useRemote(`${workflow.id}:${revision}`, signal => api.audit(workflow.id, signal), () => !terminal.has(workflow.status));
  return <section className="panel"><h2>Activity log</h2><p className="muted">Persisted events from scanning through review.</p>{result.error && <Notice error>{result.error} <button onClick={result.refresh}>Retry</button></Notice>}{result.loading && !result.data && <Notice>Loading events…</Notice>}{result.data?.length === 0 && <Empty>No events recorded yet.</Empty>}<ol className="timeline">{result.data?.map(event => <li key={event.id}><span className={`event-dot ${event.event_status.toLowerCase()}`} /><div className="heading-row"><strong>{readable(event.event_type)}</strong><small>{date(event.created_at)}</small></div><p>{event.message}</p><Badge value={event.event_status} /></li>)}</ol></section>;
}
function ReportView({ workflow, revision }: { workflow: Workflow; revision: number }) {
  const result = useRemote(`${workflow.id}:${revision}`, signal => api.report(workflow.id, signal));
  const report = result.data;
  const arrays = ['findings', 'patches', 'validations', 'reviews', 'unresolved_findings'] as const;
  return <section className="panel"><div className="section-heading"><h2>Workflow report</h2><div className="button-row"><button onClick={result.refresh}>Refresh</button><button disabled={!report} onClick={() => download(`${workflow.id}-report.json`, JSON.stringify(report, null, 2), 'application/json')}>Download JSON ↓</button></div></div><p className="muted">A snapshot of persisted evidence and review decisions.</p>{result.error && <Notice error>{result.error}</Notice>}{result.loading && !report && <Notice>Loading report…</Notice>}{report && <><EvidenceErrors errors={report.evidence_errors} /><div className="report-counts">{arrays.map(key => <div key={key}><strong>{Array.isArray(report[key]) ? report[key].length : '—'}</strong><span>{readable(key)}</span></div>)}</div>{Array.isArray(report.reviews) && report.reviews.length > 0 && <><h3>Review decisions</h3>{report.reviews.map((review, index) => <pre key={index}>{JSON.stringify(review, null, 2)}</pre>)}</>}<details><summary>Complete report</summary><pre>{JSON.stringify(report, null, 2)}</pre></details></>}</section>;
}
