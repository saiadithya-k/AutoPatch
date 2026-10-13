export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export interface Workflow {
  id: string; repository_path: string; status: string; current_stage?: string | null;
  max_retries: number; created_at: string; started_at?: string | null;
  completed_at?: string | null; error_message?: string | null;
  total_findings?: number; processed_findings?: number; reviewable_count?: number;
  failed_count?: number; approved_count?: number; rejected_count?: number;
  outcome?: string | null; errors?: string[];
  evidence_errors?: { record_id: string; field: string; error: string }[];
}
export interface Finding {
  id: string; workflow_id?: string; type: string; severity: string; status: string;
  file_path: string; line_start?: number; line_end?: number; description: string;
  code_snippet?: string; risk_score?: number | null; priority?: string | null;
  risk_reasoning?: string | null; tool: string; cwe?: string; rule_id?: string;
}
export interface Patch {
  id: string; workflow_id?: string; vulnerability_id: string; attempt_number: number;
  patch_content: string; explanation?: string; files_changed: string[]; status: string;
  parent_patch_id?: string | null; validation_id?: string | null; created_at: string;
  evidence_errors?: { record_id: string; field: string; error: string }[];
}
export interface Validation {
  id: string; status: string; patch_applied: boolean; syntax_check_passed: boolean;
  tests_passed: boolean; tests_run?: number; test_exit_code?: number | null;
  test_stdout?: string; test_stderr?: string; security_scan_passed: boolean;
  original_vulnerability_resolved: boolean; new_findings_count: number;
  regression_detected: boolean; failure_reason?: string; failure_category?: string;
  validation_logs?: string; sandbox_type: string; duration: number;
  scanner_metadata?: { scan_status?: string; coverage_complete?: boolean; required_scanners?: string[]; errors?: string[]; [key: string]: unknown };
}
export interface Risk { risk_score: number; priority: string; reasoning: string; assessment_method: string }
export interface Context {
  surrounding_code: string; context_window_start: number; language: string;
  enclosing_scope?: { name: string } | null;
  related_tests: { file_path: string; test_names: string[] }[]; warnings: string[];
}
export interface Retry {
  attempt_number: number; patch_id: string; status: string;
  parent_patch_id?: string; failure_reason?: string; failure_category?: string;
}
export interface Audit { id: string; event_type: string; event_status: string; message?: string; created_at: string }
export type Report = Record<string, unknown>;
