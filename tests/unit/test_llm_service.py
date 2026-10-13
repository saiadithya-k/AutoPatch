"""Unit tests for Phase 3 LLM Provider Service, structured parsing, and hybrid risk reasoning."""

import json
from unittest.mock import MagicMock, patch
import httpx
import pytest
from pydantic import BaseModel, Field

from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.models.risk_assessment import AssessmentMethod, PriorityLevel
from backend.models.vulnerability import Severity, VulnerabilityFinding
from backend.services.llm.base import LLMProvider
from backend.services.llm.exceptions import (
    LLMAuthenticationError,
    LLMConfigurationError,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseMalformedError,
    LLMTimeoutError,
    LLMValidationError,
)
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.openai_provider import OpenAIProvider
from backend.services.llm.schemas import LLMMessage, LLMRiskAnalysis
from backend.services.llm.service import LLMService
from backend.services.risk_engine import RiskEngine


class SimpleTestSchema(BaseModel):
    title: str
    count: int
    tags: list[str] = Field(default_factory=list)


def test_provider_uses_configured_timeout_and_explicit_override(monkeypatch):
    from backend.config import Settings
    monkeypatch.setattr("backend.services.llm.openai_provider.get_settings",
                        lambda: Settings(LLM_TIMEOUT=180))
    assert OpenAIProvider(api_key="local-test")._timeout == 180
    assert OpenAIProvider(api_key="local-test", timeout=12)._timeout == 12


# ==============================================================================
# 1. Base Provider & Mock Provider Tests
# ==============================================================================

def test_mock_provider_basic_text_generation():
    provider = MockLLMProvider(canned_content="Hello security world")
    response = provider.generate_text("Test prompt")

    assert response.content == "Hello security world"
    assert response.model == "mock-model-v1"
    assert response.usage["total_tokens"] > 0
    assert len(provider.call_history) == 1


def test_mock_provider_structured_schema_generation():
    provider = MockLLMProvider()
    response = provider.generate_text("Analyze finding", response_schema=LLMRiskAnalysis)

    assert response.parsed is not None
    assert isinstance(response.parsed, LLMRiskAnalysis)
    assert len(response.parsed.summary) > 0
    assert len(response.parsed.attack_vector) > 0


def test_mock_provider_error_simulations():
    # Authentication error
    p_auth = MockLLMProvider(raise_auth_error=True)
    with pytest.raises(LLMAuthenticationError):
        p_auth.generate_text("test")

    # Timeout error
    p_timeout = MockLLMProvider(raise_timeout=True)
    with pytest.raises(LLMTimeoutError):
        p_timeout.generate_text("test")

    # Rate limit error
    p_rate = MockLLMProvider(raise_rate_limit=True)
    with pytest.raises(LLMRateLimitError):
        p_rate.generate_text("test")

    # Unavailable error
    p_unavail = MockLLMProvider(raise_unavailable=True)
    with pytest.raises(LLMProviderUnavailableError):
        p_unavail.generate_text("test")

    # Malformed JSON
    p_malformed = MockLLMProvider(canned_content="{ not valid json }")
    with pytest.raises(LLMResponseMalformedError):
        p_malformed.generate_text("test", response_schema=SimpleTestSchema)

    # Schema validation failure
    p_invalid = MockLLMProvider(canned_content=json.dumps({"title": "test", "count": "not_an_int_and_missing_tags_is_fine_but_this_fails"}))
    with pytest.raises(LLMValidationError):
        p_invalid.generate_text("test", response_schema=SimpleTestSchema)


# ==============================================================================
# 2. OpenAI Provider Tests (Isolated via Mock HTTP Responses)
# ==============================================================================

def test_openai_provider_missing_key_raises_configuration_error():
    provider = OpenAIProvider(api_key="")
    with pytest.raises(LLMConfigurationError):
        provider.generate_text("test prompt")


def test_openai_provider_successful_structured_output():
    provider = OpenAIProvider(api_key="sk-fake-test-key-for-unit-tests", model="gpt-4o")

    mock_resp_payload = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 123456789,
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps({
                        "summary": "Command injection vulnerability in ping utility",
                        "attack_vector": "Attacker supplies shell metacharacters in target_host parameter",
                        "impact_analysis": "Remote code execution with privileges of web server user",
                        "mitigation_guidance": "Use subprocess.run with argument list instead of shell string",
                        "confidence_assessment": "High confidence true positive",
                    })
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 40, "total_tokens": 90}
    }

    mock_http_response = MagicMock(spec=httpx.Response)
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = mock_resp_payload

    with patch.object(httpx.Client, "post", return_value=mock_http_response):
        response = provider.generate_text("Analyze code", response_schema=LLMRiskAnalysis)

        assert response.content is not None
        assert isinstance(response.parsed, LLMRiskAnalysis)
        assert response.parsed.summary == "Command injection vulnerability in ping utility"
        assert response.parsed.attack_vector.startswith("Attacker")
        assert response.usage["total_tokens"] == 90


def test_openai_provider_http_401_authentication_failure():
    provider = OpenAIProvider(api_key="sk-invalid-test-key")

    mock_http_response = MagicMock(spec=httpx.Response)
    mock_http_response.status_code = 401
    mock_http_response.text = '{"error": {"message": "Incorrect API key provided"}}'

    with patch.object(httpx.Client, "post", return_value=mock_http_response):
        with pytest.raises(LLMAuthenticationError):
            provider.generate_text("Hello")


def test_openai_provider_http_429_rate_limit():
    provider = OpenAIProvider(api_key="sk-fake-key")

    mock_http_response = MagicMock(spec=httpx.Response)
    mock_http_response.status_code = 429
    mock_http_response.text = '{"error": {"message": "Rate limit reached"}}'

    with patch.object(httpx.Client, "post", return_value=mock_http_response):
        with pytest.raises(LLMRateLimitError):
            provider.generate_text("Hello")


def test_openai_provider_http_500_provider_unavailable():
    provider = OpenAIProvider(api_key="sk-fake-key")

    mock_http_response = MagicMock(spec=httpx.Response)
    mock_http_response.status_code = 503
    mock_http_response.text = '{"error": {"message": "Service Unavailable"}}'

    with patch.object(httpx.Client, "post", return_value=mock_http_response):
        with pytest.raises(LLMProviderUnavailableError):
            provider.generate_text("Hello")


def test_openai_provider_timeout_exception():
    provider = OpenAIProvider(api_key="sk-fake-key", timeout=1.0)

    with patch.object(httpx.Client, "post", side_effect=httpx.TimeoutException("Connection timed out")):
        with pytest.raises(LLMTimeoutError):
            provider.generate_text("Hello")


def test_openai_provider_malformed_json_response():
    provider = OpenAIProvider(api_key="sk-fake-key")

    mock_http_response = MagicMock(spec=httpx.Response)
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "choices": [{"message": {"content": "This is raw text, not JSON"}}]
    }

    with patch.object(httpx.Client, "post", return_value=mock_http_response):
        with pytest.raises(LLMResponseMalformedError):
            provider.generate_text("test", response_schema=LLMRiskAnalysis)


# ==============================================================================
# 3. LLM Service Tests (Manager & Hybrid Workflow)
# ==============================================================================

def test_llm_service_unconfigured_fallback():
    service = LLMService(provider=None)
    assert service.is_configured is False

    # Should safely return None without throwing exceptions
    result = service.generate_structured("prompt", response_schema=SimpleTestSchema)
    assert result is None


def test_llm_service_with_mock_provider():
    mock_p = MockLLMProvider()
    service = LLMService(provider=mock_p)
    assert service.is_configured is True

    finding = VulnerabilityFinding(
        id="VULN-001",
        tool="bandit",
        rule_id="B605",
        type="Command Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=14,
        code_snippet="os.system(cmd)",
        description="os.system command injection",
    )

    analysis = service.enhance_risk_reasoning(finding, baseline_reasoning="Base reasoning string")
    assert analysis is not None
    assert isinstance(analysis, LLMRiskAnalysis)

    hybrid = LLMService.format_hybrid_reasoning("Base reasoning string", analysis)
    assert "Base reasoning string" in hybrid
    assert "[LLM Contextual Analysis]" in hybrid
    assert "• Summary:" in hybrid


# ==============================================================================
# 4. Hybrid Risk Assessment Integration Tests
# ==============================================================================

def test_hybrid_risk_assessment_preserves_deterministic_scores():
    """Verify that adding LLM reasoning does NOT alter the deterministic numeric scores."""
    risk_engine = RiskEngine()
    mock_p = MockLLMProvider()
    llm_service = LLMService(provider=mock_p)

    agent_pure_rules = RiskAssessmentAgent(risk_engine=risk_engine, enable_llm=False)
    agent_hybrid_llm = RiskAssessmentAgent(risk_engine=risk_engine, llm_service=llm_service, enable_llm=True)

    finding1 = VulnerabilityFinding(
        id="VULN-HYB-01",
        tool="bandit",
        rule_id="B605",
        type="Command Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=14,
        code_snippet="os.system(cmd)",
        description="os.system command injection",
    )

    finding2 = VulnerabilityFinding(
        id="VULN-HYB-01",
        tool="bandit",
        rule_id="B605",
        type="Command Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=14,
        code_snippet="os.system(cmd)",
        description="os.system command injection",
    )

    res_pure = agent_pure_rules.assess([finding1], persist=False)[0]
    res_hybrid = agent_hybrid_llm.assess([finding2], persist=False)[0]

    # Scores and priority MUST be identical
    assert res_pure.risk_assessment.risk_score == res_hybrid.risk_assessment.risk_score
    assert res_pure.risk_assessment.severity_score == res_hybrid.risk_assessment.severity_score
    assert res_pure.risk_assessment.exploitability == res_hybrid.risk_assessment.exploitability
    assert res_pure.risk_assessment.business_impact == res_hybrid.risk_assessment.business_impact
    assert res_pure.risk_assessment.priority == res_hybrid.risk_assessment.priority

    # Assessment method indicates hybrid
    assert res_pure.risk_assessment.assessment_method == AssessmentMethod.DETERMINISTIC_RULES
    assert res_hybrid.risk_assessment.assessment_method == AssessmentMethod.HYBRID_LLM
    assert "[LLM Contextual Analysis]" in res_hybrid.risk_assessment.reasoning


def test_hybrid_risk_assessment_graceful_fallback_on_llm_failure():
    """When LLM raises timeout or auth errors, assessment completes cleanly with deterministic reasoning."""
    risk_engine = RiskEngine()
    mock_p = MockLLMProvider(raise_timeout=True)
    llm_service = LLMService(provider=mock_p)

    agent = RiskAssessmentAgent(risk_engine=risk_engine, llm_service=llm_service, enable_llm=True)

    finding = VulnerabilityFinding(
        id="VULN-FALLBACK-01",
        tool="bandit",
        rule_id="B608",
        type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.MEDIUM,
        file_path="database.py",
        line_start=20,
        description="SQL injection",
    )

    prioritized = agent.assess([finding], persist=False)
    assert len(prioritized) == 1
    p = prioritized[0]

    # Fallback to deterministic method
    assert p.risk_assessment.risk_score > 0.0
    assert p.risk_assessment.assessment_method == AssessmentMethod.DETERMINISTIC_RULES
    assert "Vulnerability 'SQL Injection'" in p.risk_assessment.reasoning
