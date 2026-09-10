# AutoPatch --- Product Requirements Document (PRD)

## 1. Product Overview

**AutoPatch** is an agentic AI system for automated software
vulnerability remediation. It is designed to move from source-code
analysis through vulnerability assessment, patch generation, validation,
retry, and human approval.

The product is organized around four specialized agents:

1.  Scanning Agent
2.  Risk-Assessment Agent
3.  Patch-Generation Agent
4.  Validation Agent

An Orchestration Layer coordinates the agents, shared state, tool
execution, retry operations, logging, and reporting.

## 2. Problem Statement

Existing SAST/DAST-oriented security workflows can identify potential
vulnerabilities, but vulnerability triaging, contextual risk assessment,
remediation, and validation can still require significant developer
effort.

AutoPatch addresses this by integrating detection, contextual risk
assessment, patch generation, automated validation, feedback-driven
retry, and human approval into one workflow.

## 3. Goals

-   Accept a source-code repository or source-code files.
-   Detect potential vulnerabilities.
-   Identify affected files and code locations.
-   Classify and prioritize findings using severity, exploitability,
    context, and impact.
-   Generate candidate code-level fixes.
-   Validate generated patches in an isolated environment.
-   Re-scan after patching.
-   Retry failed patches using validation feedback.
-   Present successfully validated patches for developer review.
-   Allow approval or rejection.
-   Maintain vulnerability records, patch history, validation results,
    and audit information.
-   Produce a security/remediation report.
-   Support integration with Git/GitHub and CI/CD workflows.

## 4. Non-Goals / Safety Boundaries

-   AutoPatch must not blindly accept an LLM-generated patch.
-   A generated patch must not be considered successful solely because
    the LLM produced it.
-   The system must not automatically merge a generated patch into the
    production/main codebase.
-   Generated patches should be tested in an isolated environment when
    execution is required.
-   The report does not specify a requirement for autonomous production
    deployment.

## 5. Users

### Primary User

Developer / software engineer responsible for reviewing and remediating
security findings.

### Secondary Stakeholder

Security engineer or project reviewer who needs traceability of
detection, assessment, patching, and validation.

## 6. Functional Requirements

  -----------------------------------------------------------------------
  ID                                  Requirement
  ----------------------------------- -----------------------------------
  UR1                                 Accept source-code repository or
                                      source-code files.

  UR2                                 Automatically scan the codebase for
                                      known vulnerability patterns.

  UR3                                 Identify vulnerability type,
                                      affected file, and code location.

  UR4                                 Classify vulnerabilities by
                                      severity and exploitability.

  UR5                                 Assess contextual risk and assign a
                                      priority score.

  UR6                                 Order findings according to risk.

  UR7                                 Generate a proposed code-level
                                      patch.

  UR8                                 Validate patches in an isolated
                                      environment and execute appropriate
                                      tests.

  UR9                                 Re-scan modified code to determine
                                      whether the original vulnerability
                                      remains.

  UR10                                Feed validation failures back to
                                      patch generation and retry up to a
                                      configurable limit.

  UR11                                Generate a report containing
                                      vulnerabilities, risk scores, patch
                                      status, validation results, and
                                      code differences.

  UR12                                Allow developers to review
                                      generated patches and validation
                                      information.

  UR13                                Allow patch approval or rejection
                                      before application/merge into the
                                      main codebase.

  UR14                                Maintain audit information for
                                      findings, decisions, patches,
                                      validation, and retries.
  -----------------------------------------------------------------------

## 7. Non-Functional Requirements

### Performance

The scan-to-patch workflow should remain practical for moderately sized
codebases. Detailed LLM processing should be focused on relevant
findings rather than the complete repository.

### Reliability

The same input, configuration, and environment should produce reliable
and consistent behavior. Generated patches must be validated before
being presented as successful remediation.

### Scalability

The modular architecture should support larger codebases and allow
individual components to be optimized independently.

### Security

The system should consider prompt injection, unauthorized tool
invocation, unsafe code execution, malicious repository content,
unauthorized source modification, and improper external-service access.

### Usability

The user should be able to understand the vulnerability, location,
severity, risk score, proposed patch, validation state, failure reason,
and final remediation state.

### Maintainability

Agents, scanners, LLM providers, testing tools, database, and dashboard
should be replaceable or extendable without redesigning the entire
system.

### Auditability

Important agent actions, vulnerability findings, risk assessments,
patches, validation results, tests, retries, and patch history should be
recorded.

## 8. Core User Journey

1.  User supplies a repository.
2.  AutoPatch starts a workflow.
3.  Scanning Agent discovers potential vulnerabilities.
4.  Findings are stored as vulnerability records.
5.  Risk-Assessment Agent evaluates and prioritizes them.
6.  Patch-Generation Agent creates a candidate patch for a prioritized
    finding.
7.  Validation Agent applies the patch to an isolated copy.
8.  Tests and security re-scan are executed.
9.  If validation fails, feedback is sent back for another patch
    attempt.
10. If validation succeeds, the patch becomes `READY_FOR_REVIEW`.
11. Developer reviews the vulnerability, risk, diff, and validation
    evidence.
12. Developer approves or rejects.
13. The workflow history and final decision are retained.

## 9. Success Criteria

The core demonstration is successful when a vulnerable Python repository
can move through:

`SCAN → ASSESS → PRIORITIZE → GENERATE → VALIDATE → RETRY IF NEEDED → READY FOR REVIEW → APPROVE/REJECT → REPORT`

The system must be able to demonstrate both a successful validation path
and a validation-failure/retry path.

## 10. Technology Direction From Project Report

-   Python 3.10+
-   LangGraph or custom Python orchestration
-   Claude API / OpenAI API or equivalent
-   Bandit
-   Semgrep
-   Git / GitHub API
-   Docker
-   Pytest / language-native test runner
-   SQLite / PostgreSQL
-   FastAPI
-   React or HTML/JavaScript
-   GitHub Actions
