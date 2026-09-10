# AutoPatch — Phase 2 Finalization & Phase 3 Walkthrough

## Executive Summary

- **Phase 2 Finalization**: Verified and audited the complete Phase 2 baseline. Fixed `Any` type hint in `tests/vulnerable_project/app.py` while preserving all intentional vulnerabilities. Reinforced scanner failure semantics in `ScanningAgent` (`COMPLETED`, `DEGRADED`, `FAILED`). Verified deterministic risk calculations, priority thresholds, database transitions, and API routes.
- **Phase 3 LLM Service**: Built a provider-independent LLM service layer (`backend/services/llm/`) with abstract `LLMProvider`, `OpenAIProvider`, `MockLLMProvider`, and `LLMService`. Enforced structured JSON output validation via Pydantic schemas (`LLMRiskAnalysis`), prompt-injection resistant templates (`prompts/risk_assessment.md`), untrusted data boundaries, and safe offline execution with zero API keys required.

```text
                               ┌──────────────────────────┐
                               │  Target Repository Path  │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │      Scanning Agent      │
                               │  (Graceful Degradation)  │
                               └──────┬────────────┬──────┘
                                      │            │
                         ┌────────────┴──┐      ┌──┴─────────────┐
                         │ BanditRunner  │      │ SemgrepRunner  │
                         └────────────┬──┘      └──┬─────────────┘
                                      │            │
                                      ▼            ▼
                               ┌──────────────────────────┐
                               │  Normalized Findings     │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │  Risk-Assessment Agent   │
                               │                          │
                               │  1. Deterministic Engine │
                               │     (Authoritative)      │
                               │  2. Optional Hybrid LLM  │
                               │     Contextual Reason    │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │ SQLite Database Layer    │
                               │ (Workflows/Vulns/Risk)   │
                               └────────────┬─────────────┘
                                            │
                                            ▼
                               ┌──────────────────────────┐
                               │    FastAPI HTTP API      │
                               └──────────────────────────┘
```

---

## 1. Phase 2 Finalization & Audit Results

1. **Vulnerable Demo Fix**:
   - `tests/vulnerable_project/app.py`: Added missing `from typing import Any` import to prevent syntax/runtime import issues.
   - Preserved all intentional vulnerabilities (Command Injection `os.system`, Dynamic `eval`, Raw SQL query in `database.py`).
2. **Scanner Failure Semantics**:
   - Updated `ScanningAgent.scan()` and `_persist_findings()` to distinguish:
     - `COMPLETED`: Both Bandit and Semgrep completed successfully.
     - `DEGRADED`: One scanner failed, but the other completed and yielded normalized findings.
     - `FAILED`: Both scanners failed or scanner infrastructure was unavailable (workflow marked as `FAILED` with diagnostics recorded in metadata; never reporting clean repository on scanner failure).
3. **Deterministic Risk Engine Verification**:
   - Confirmed formula: $\text{Risk} = 0.35S + 0.25E + 0.25I + 0.15C \in [0.0, 10.0]$.
   - Priority boundaries verified: $\ge 8.5 \to \text{CRITICAL}$, $\ge 7.0 \to \text{HIGH}$, $\ge 4.0 \to \text{MEDIUM}$, $< 4.0 \to \text{LOW}$.
   - Verified 100% deterministic reproducibility across repeated runs.
4. **Database State Lifecycle**:
   - Vulnerability lifecycle verified: `DETECTED` $\to$ `ASSESSED` $\to$ `PRIORITIZED`.
   - Workflow stage updated to `RISK_ASSESSMENT_COMPLETE`.

---

## 2. Phase 3 Architecture: Provider-Independent LLM Service

Delivered in `backend/services/llm/`:

1. **`exceptions.py`**:
   - `LLMError`, `LLMConfigurationError`, `LLMProviderUnavailableError`, `LLMAuthenticationError`, `LLMRateLimitError`, `LLMTimeoutError`, `LLMResponseMalformedError`, `LLMValidationError`.
2. **`schemas.py`**:
   - `LLMMessage`: Chat message envelope (`role`, `content`).
   - `LLMResponse`: Structured envelope with `content`, `parsed`, `model`, and `usage`.
   - `LLMRiskAnalysis`: Validated Pydantic schema for contextual security triage (`summary`, `attack_vector`, `impact_analysis`, `mitigation_guidance`, `confidence_assessment`).
   - `LLMPatchSuggestion`: Schema placeholder for Phase 4.
3. **`base.py`**:
   - Abstract `LLMProvider` defining `generate(...)` and `generate_text(...)`.
4. **`openai_provider.py`**:
   - Safe HTTP client implementation calling OpenAI chat completions.
   - Validates configuration from environment (`OPENAI_API_KEY`, `LLM_MODEL`).
   - Never logs or exposes API keys.
   - Translates HTTP errors (401, 429, 5xx, timeouts) into strongly typed exceptions.
   - Decodes JSON and validates against Pydantic response schemas.
5. **`mock_provider.py`**:
   - Full mock provider for offline testing of text generation, structured schemas, and error simulations (timeouts, 401s, 429s, malformed responses).
6. **`service.py`**:
   - `LLMService` manager providing structured generation, template loading, and hybrid reasoning integration.
7. **`prompts/`**:
   - `prompts/risk_assessment.md`: Active prompt with untrusted data boundaries and schema specification.
   - `prompts/patch_generation.md`: Placeholder for Phase 4.
   - `prompts/retry.md`: Placeholder for Phase 6.

---

## 3. LLM Security Controls

- **Untrusted Context Isolation**: Repository code snippets are placed within `<untrusted_source_snippet>` tags and treated as passive data.
- **Prompt Injection Defense**: System prompts explicitly forbid following commands inside untrusted snippets.
- **No Code/Shell Execution**: LLM service does not execute shell commands or repository code.
- **Deterministic Authoritativeness**: The deterministic `RiskEngine` remains authoritative for numeric scores; LLM reasoning enriches qualitative explanation in hybrid mode.
- **Zero-Key Offline Capability**: The entire application and test suite execute without requiring an external API key.

---

## 4. Test Verification Results

All **69 tests passed** across the complete test suite:

- Full suite: `python -m pytest -q` $\to$ **69 passed**
- Unit tests: `python -m pytest -q tests/unit` $\to$ **58 passed**
- Integration tests: `python -m pytest -q tests/integration` $\to$ **7 passed**
- Demo tests: `tests/vulnerable_project/test_app.py` $\to$ **4 passed**
