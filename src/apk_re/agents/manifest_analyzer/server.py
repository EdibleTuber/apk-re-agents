import os
from pathlib import Path

import anyio

from apk_re.agents.base.base_agent import create_agent_server, call_ollama
from apk_re.schemas import ManifestFindings

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "qwen2.5-coder:7b")

KNOWN_NORMAL_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.BILLING",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.NFC",
    "android.permission.BLUETOOTH",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.SET_ALARM",
    "com.google.android.c2dm.permission.RECEIVE",
    "com.google.android.c2dm.permission.SEND",
}

KNOWN_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
}

SYSTEM_PROMPT = """You are an Android security analyst specializing in manifest analysis.
Given an AndroidManifest.xml file, extract all security-relevant information into structured data.

For each permission:
- Set dangerous=true for permissions in the DANGEROUS category (e.g., READ_CONTACTS, ACCESS_FINE_LOCATION, CAMERA, READ_SMS, CALL_PHONE, RECORD_AUDIO, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, ACCESS_COARSE_LOCATION, READ_PHONE_STATE, READ_CALENDAR, WRITE_CALENDAR, BODY_SENSORS, SEND_SMS, RECEIVE_SMS, READ_CALL_LOG, WRITE_CALL_LOG, ADD_VOICEMAIL, USE_SIP, PROCESS_OUTGOING_CALLS, ANSWER_PHONE_CALLS, READ_PHONE_NUMBERS, ACCESS_BACKGROUND_LOCATION, ACTIVITY_RECOGNITION, BLUETOOTH_CONNECT, BLUETOOTH_SCAN, NEARBY_WIFI_DEVICES, POST_NOTIFICATIONS, READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, READ_MEDIA_AUDIO)
- Set dangerous=false for NORMAL permissions (e.g., INTERNET, ACCESS_NETWORK_STATE, VIBRATE, WAKE_LOCK, RECEIVE_BOOT_COMPLETED, FOREGROUND_SERVICE, ACCESS_WIFI_STATE, BILLING, REQUEST_INSTALL_PACKAGES)

Extract ALL activities, services, and receivers declared in the manifest:
- Activities are declared with <activity> tags. Extract EVERY one, including the main launcher activity.
- Services are declared with <service> tags.
- Receivers are declared with <receiver> tags.
- Do NOT put activities in the services or receivers lists, or vice versa. Match the XML tag type.

For each component:
- Set exported=true if android:exported="true" or if it has intent-filters (implicitly exported)
- List all intent-filter actions

Be thorough. Extract every permission and every component. Do not skip any."""


def create_manifest_analyzer_server():
    server = create_agent_server("manifest_analyzer")

    def _analyze_manifest_impl(manifest_path: str) -> str:
        path = Path(manifest_path)
        if not path.is_absolute():
            path = Path("/work") / path
        if not path.exists():
            return f"Error: file not found: {path}"

        manifest_content = path.read_text()
        findings = call_ollama(
            prompt=f"Analyze this AndroidManifest.xml and extract all permissions, activities, services, and receivers:\n\n{manifest_content}",
            output_schema=ManifestFindings,
            ollama_host=OLLAMA_HOST,
            model=MODEL_NAME,
            system_prompt=SYSTEM_PROMPT,
        )

        for perm in findings.permissions:
            if perm.name in KNOWN_NORMAL_PERMISSIONS:
                perm.dangerous = False
            elif perm.name in KNOWN_DANGEROUS_PERMISSIONS:
                perm.dangerous = True

        return findings.model_dump_json(indent=2)

    @server.tool()
    async def analyze_manifest(manifest_path: str) -> str:
        """Analyze an AndroidManifest.xml file and extract security-relevant findings.

        Args:
            manifest_path: Path to AndroidManifest.xml on the shared volume.
        """
        return await anyio.to_thread.run_sync(_analyze_manifest_impl, manifest_path)

    return server


if __name__ == "__main__":
    server = create_manifest_analyzer_server()
    server.run(transport="sse")
