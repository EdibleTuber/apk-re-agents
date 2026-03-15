import json
import logging
import os
from pathlib import Path

import anyio
import httpx

from apk_re.agents.base.base_agent import create_agent_server
from apk_re.schemas import MobSFCertificate, MobSFFindings

logger = logging.getLogger(__name__)

MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "changeme")
SCAN_TIMEOUT = 180  # seconds


def _parse_certificate(report: dict) -> MobSFCertificate | None:
    cert_data = report.get("certificate_analysis", {})
    if not cert_data:
        return None
    findings = [
        f"{sev}: {desc}"
        for sev, desc in cert_data.get("certificate_findings", [])
    ]
    subject = issuer = algorithm = valid_from = valid_to = None
    for item in cert_data.get("certificate_info", []):
        if isinstance(item, dict):
            subject = item.get("subject") or subject
            issuer = item.get("issuer") or issuer
            algorithm = item.get("sha256_digest_algorithm") or algorithm
            valid_from = item.get("valid_from") or valid_from
            valid_to = item.get("valid_to") or valid_to
    return MobSFCertificate(
        subject=subject, issuer=issuer, algorithm=algorithm,
        valid_from=valid_from, valid_to=valid_to, findings=findings[:20],
    )


def _parse_apkid(report: dict) -> dict[str, list[str]]:
    return {
        fname: detections
        for fname, detections in report.get("apkid", {}).items()
        if isinstance(detections, list) and detections
    }


def _parse_manifest_issues(report: dict) -> list[dict[str, str]]:
    issues = []
    for item in report.get("manifest_analysis", {}).get("manifest_findings", []):
        if isinstance(item, dict):
            issues.append({
                "title": str(item.get("title", ""))[:100],
                "severity": str(item.get("severity", "")),
                "description": str(item.get("description", ""))[:200],
            })
    return issues[:30]


def _parse_code_issues(report: dict) -> list[dict[str, str]]:
    """Extract high/warning severity code analysis hits only."""
    issues = []
    for title, detail in report.get("code_analysis", {}).get("findings", {}).items():
        if not isinstance(detail, dict):
            continue
        severity = str(detail.get("metadata", {}).get("severity", "")).lower()
        if severity not in ("high", "warning", "error"):
            continue
        for f in detail.get("files", [])[:3]:
            issues.append({
                "title": str(title)[:100],
                "severity": severity,
                "file": str(f.get("file_path", "") if isinstance(f, dict) else f)[:150],
            })
    return issues[:40]


def _parse_niap(report: dict) -> list[dict[str, str]]:
    return [
        {
            "check": str(check)[:80],
            "status": str(detail.get("status", ""))[:20],
            "description": str(detail.get("description", ""))[:150],
        }
        for check, detail in report.get("niap_analysis", {}).items()
        if isinstance(detail, dict)
    ][:25]


def _parse_network_security(report: dict) -> list[str]:
    issues = []
    for item in report.get("network_security", {}).get("network_findings", []):
        if isinstance(item, dict):
            issues.append(str(item.get("description", item))[:150])
        elif isinstance(item, str):
            issues.append(item[:150])
    return issues[:15]


def _parse_vulnerable_libs(report: dict) -> list[str]:
    libs = []
    for lib in report.get("libraries", []):
        name = lib.get("name") or lib.get("lib") if isinstance(lib, dict) else lib
        if name:
            libs.append(str(name))
    return libs[:20]


def _analyze_with_mobsf_impl(apk_path: str) -> str:
    path = Path(apk_path)
    if not path.is_absolute():
        path = Path("/work") / path
    if not path.exists():
        return json.dumps({"error": f"APK not found: {path}"})

    headers = {"Authorization": MOBSF_API_KEY}

    try:
        with httpx.Client(base_url=MOBSF_URL, timeout=SCAN_TIMEOUT) as client:
            logger.info("MobSF: uploading %s", path.name)
            with open(path, "rb") as fh:
                resp = client.post(
                    "/api/v1/upload",
                    files={"file": (path.name, fh, "application/octet-stream")},
                    headers=headers,
                )
            resp.raise_for_status()
            upload = resp.json()
            file_hash = upload.get("hash")
            file_name = upload.get("file_name")
            if not file_hash or not file_name:
                return json.dumps({"error": "MobSF upload response missing hash or file_name"})
            logger.info("MobSF: upload done, hash=%s — starting scan", file_hash)

            resp = client.post(
                "/api/v1/scan",
                data={"scan_type": "apk", "file_name": file_name, "hash": file_hash},
                headers=headers,
            )
            resp.raise_for_status()
            logger.info("MobSF: scan complete — fetching report")

            resp = client.post(
                "/api/v1/report_json",
                data={"hash": file_hash},
                headers=headers,
            )
            resp.raise_for_status()
            report = resp.json()

    except httpx.HTTPError as exc:
        logger.exception("MobSF HTTP error")
        return json.dumps({"error": f"MobSF HTTP error: {exc}"})
    except Exception as exc:
        logger.exception("MobSF unexpected error")
        return json.dumps({"error": f"MobSF error: {exc}"})

    try:
        findings = MobSFFindings(
            app_name=report.get("app_name"),
            package_name=report.get("package_name"),
            version=report.get("version_name"),
            min_sdk=str(report.get("min_sdk", "")),
            target_sdk=str(report.get("target_sdk", "")),
            certificate=_parse_certificate(report),
            apkid=_parse_apkid(report),
            vulnerable_libraries=_parse_vulnerable_libs(report),
            manifest_issues=_parse_manifest_issues(report),
            code_issues=_parse_code_issues(report),
            niap_findings=_parse_niap(report),
            network_security_issues=_parse_network_security(report),
        )
    except Exception as exc:
        logger.exception("MobSF report parsing error")
        return json.dumps({"error": f"MobSF report parsing error: {exc}"})
    return findings.model_dump_json(indent=2)


def create_mobsf_analyzer_server():
    server = create_agent_server("mobsf_analyzer")

    @server.tool()
    async def analyze_with_mobsf(apk_path: str) -> str:
        """Upload an APK to MobSF and return structured static analysis findings.

        Runs MobSF's full static analysis: cert analysis, manifest rule checks,
        dangerous API pattern matching, apkid packer detection, NIAP compliance.
        No LLM involved — pure rule-based analysis.

        Args:
            apk_path: Path to the APK file on the shared volume.
        """
        return await anyio.to_thread.run_sync(_analyze_with_mobsf_impl, apk_path)

    return server


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = create_mobsf_analyzer_server()
    server.run(transport="sse")
