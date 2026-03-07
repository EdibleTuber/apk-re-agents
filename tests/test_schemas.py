import json
from apk_re.schemas import (
    JobRequest,
    JobStatus,
    ManifestFindings,
    Permission,
    Component,
    StringFinding,
    EndpointFinding,
    CodeAnalysisSummary,
    NetworkFinding,
    AgentResult,
)


def test_job_request_roundtrip():
    job = JobRequest(apk_path="/data/shared/input/test.apk")
    data = job.model_dump_json()
    restored = JobRequest.model_validate_json(data)
    assert restored.apk_path == "/data/shared/input/test.apk"
    assert restored.job_id is not None


def test_manifest_findings_structure():
    findings = ManifestFindings(
        permissions=[Permission(name="android.permission.INTERNET", dangerous=False)],
        activities=[Component(name=".MainActivity", exported=True, intent_filters=["android.intent.action.MAIN"])],
        services=[],
        receivers=[],
    )
    data = json.loads(findings.model_dump_json())
    assert data["permissions"][0]["name"] == "android.permission.INTERNET"
    assert data["activities"][0]["exported"] is True


def test_string_finding():
    finding = StringFinding(
        value="AIzaSyD-example-key",
        category="api_key",
        source_file="com/example/Config.java",
        line_number=42,
        entropy=4.2,
    )
    assert finding.category == "api_key"


def test_endpoint_finding():
    finding = EndpointFinding(
        url="https://api.example.com/v1/users",
        http_method="POST",
        source_class="com.example.ApiClient",
        request_fields={"username": "string", "password": "string"},
        response_fields={"token": "string"},
    )
    assert finding.http_method == "POST"


def test_agent_result_serialization():
    result = AgentResult(
        agent_name="manifest_analyzer",
        job_id="abc-123",
        status="success",
        findings={"permissions_count": 5},
    )
    data = json.loads(result.model_dump_json())
    assert data["agent_name"] == "manifest_analyzer"
    assert data["status"] == "success"
