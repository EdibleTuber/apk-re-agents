# Prompt Tuning Plan — Round 2

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix remaining false positives and regressions from Round 1. Get each agent to produce genuinely useful output on ergatta.apk.

**Baseline:** `findings_dump.txt` from Round 1 run.

**Test loop:** After each task, rebuild affected container(s) and re-run pipeline. Compare to baseline.

---

## Task 1: String Extractor — Library Path Filtering + Kotlin Mangled Names

**Problem:** ~150 false positives remain. Two root causes:
1. No library path filtering — okio/Base64.java, slf4j, apache commons, androidx/compose all scanned
2. Kotlin name-mangled methods pass all existing filters (e.g., `m5293surfaceColorAtElevationcq6XJ1M`, `createGuidelineFromAbsoluteRight-0680j_4`, `getSTYLEABLE_VECTOR_DRAWABLE_GROUP_PIVOT_X`)

**File:** `src/apk_re/agents/string_extractor/server.py`

**Fixes:**

### 1a. Add LIBRARY_PATH_SEGMENTS filtering
Skip files in library paths before scanning. Reuse the same list from other agents plus add missing ones:
```python
LIBRARY_PATH_SEGMENTS = (
    "/io/netty/", "/okio/", "/okhttp3/", "/retrofit2/",
    "/dagger/", "/hilt_aggregated_deps/", "/androidx/",
    "/com/google/", "/com/android/", "/kotlin/", "/kotlinx/",
    "/org/apache/", "/io/reactivex/", "/com/squareup/",
    "/com/facebook/", "/com/crashlytics/", "/net/jodah/",
    "/com/braze/", "/com/airbnb/", "/exoplayer2/",
    "/org/slf4j/", "/org/codehaus/", "/io/grpc/",
    "/com/fasterxml/", "/org/bouncycastle/",
)
```
In the file-walking loop, skip any file whose path contains a library segment.

### 1b. Filter Kotlin name-mangled methods
Add two new filters to `_is_false_positive()`:
```python
# Kotlin mangled: m<digits><methodName><hashSuffix>
# e.g., m5293surfaceColorAtElevationcq6XJ1M
KOTLIN_MANGLED_PREFIX = re.compile(r'^m\d{3,}[a-zA-Z]')

# Kotlin hash suffix: methodName-<7-8 char hash>
# e.g., createGuidelineFromAbsoluteRight-0680j_4
KOTLIN_HASH_SUFFIX = re.compile(r'-[A-Za-z0-9_]{5,10}$')
# But must also have a camelCase prefix to avoid filtering real tokens
```
A string is a Kotlin mangled name if:
- It matches `KOTLIN_MANGLED_PREFIX` (starts with `m` + 3+ digits + letter), OR
- It contains a `-` and the part after the last `-` is 5-10 alphanumeric chars AND the part before is a valid camelCase identifier

### 1c. Filter STYLEABLE getter names
```python
# Android resource styleable getters
STYLEABLE_PATTERN = re.compile(r'^(get|set)STYLEABLE_')
```

### 1d. Filter Java internal path strings
Strings matching `^[a-z]+(/[a-zA-Z][a-zA-Z0-9]*)+$` are Java class paths (e.g., `org/slf4j/impl/StaticLoggerBinder`), not secrets.

### 1e. Filter underscore-heavy config/resource names
Strings matching `^[a-z]+_[a-zA-Z0-9_]+$` where all segments are words (e.g., `config_showMenuShortcutsWhenKeyboardPresent`, `java_dagger_hilt_android-entry_point_accessors_internal_kt`) — these are resource identifiers.

**Expected outcome:** String extractor finds only real URLs, actual API keys (AIza...), and genuine secrets. False positives < 5.

**Tests:** Update existing tests. Add test cases for Kotlin mangled name filtering and library path skipping.

---

## Task 2: Code Analyzer — Fix Scoring with Clamping + Hallucination Guard

**Problem:** Despite prompt saying "0.0-1.0", the 7B model outputs 100.0 and 85.0. It also hallucinated `com.example.MyClass`. Flags still empty.

**File:** `src/apk_re/agents/code_analyzer/server.py`

**Fixes:**

### 2a. Post-process scores — clamp to 0.0-1.0
After LLM returns results, if any score > 1.0, divide by 100 and clamp:
```python
for cls in result.classes:
    if cls.relevance_score > 1.0:
        cls.relevance_score = min(cls.relevance_score / 100.0, 1.0)
```
This is more reliable than trying to get the 7B model to follow the instruction.

### 2b. Filter hallucinated classes
After LLM returns results, verify each `class_name` against the actual files that were sent to it. Remove any class that wasn't in the input:
```python
# Build set of class names from files actually sent
sent_classes = set()
for path in files_sent:
    # Convert file path to class name
    # e.g., com/ifit/glassos/Foo.java -> com.ifit.glassos.Foo
    class_name = path.replace('/', '.').replace('.java', '')
    sent_classes.add(class_name)

result.classes = [c for c in result.classes if c.class_name in sent_classes]
```

### 2c. Default flag assignment
If the LLM returns empty flags, assign a default based on the file content keywords:
```python
for cls in result.classes:
    if not cls.flags:
        # Infer from the source content
        content = file_contents.get(cls.class_name, "")
        if any(kw in content for kw in ["Http", "Socket", "Url", "Retrofit", "OkHttp"]):
            cls.flags = ["network"]
        elif any(kw in content for kw in ["Cipher", "KeyStore", "MessageDigest", "SecretKey"]):
            cls.flags = ["crypto"]
        elif any(kw in content for kw in ["SharedPreferences", "SQLite", "ContentProvider"]):
            cls.flags = ["storage"]
        else:
            cls.flags = ["other"]
```

### 2d. Add io/grpc/ to LIBRARY_PATH_SEGMENTS
The code analyzer is triaging `io.grpc.okhttp.internal.ConnectionSpec` — a library class. Add `/io/grpc/` to the filter list.

**Expected outcome:** Scores on 0.0-1.0 scale, no hallucinated classes, meaningful flags, only app-specific classes triaged.

**Tests:** Add test for score clamping. Add test for hallucination filtering.

---

## Task 3: Network Mapper — Add io/grpc/ to Library Filter

**Problem:** All 3 findings are from gRPC OkHttp library internals. Endpoint field still contains `io.grpc.okhttp` (a package name, not a URL).

**File:** `src/apk_re/agents/network_mapper/server.py`

**Fixes:**

### 3a. Add missing library paths
```python
LIBRARY_PATH_SEGMENTS = (
    "/io/netty/", "/okio/", "/okhttp3/", "/retrofit2/",
    "/dagger/", "/hilt_aggregated_deps/", "/androidx/",
    "/com/google/", "/com/android/", "/kotlin/", "/kotlinx/",
    "/org/apache/", "/io/reactivex/", "/com/squareup/",
    "/com/facebook/", "/com/crashlytics/", "/net/jodah/",
    "/com/braze/", "/com/airbnb/", "/exoplayer2/",
    "/io/grpc/", "/org/slf4j/", "/org/codehaus/",
)
```

### 3b. Post-process endpoint validation
After LLM returns results, validate the endpoint field. If it doesn't look like a URL/hostname/IP, replace with "unknown":
```python
import re
ENDPOINT_PATTERN = re.compile(
    r'^(https?://|wss?://|tcp://|udp://|\*\.|'  # URL schemes or wildcard
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'     # IP address
    r'[a-z0-9][-a-z0-9]*\.[a-z]{2,}|'            # hostname (foo.example.com)
    r'unknown$)',                                   # explicit unknown
    re.IGNORECASE
)

for finding in result.findings:
    if not ENDPOINT_PATTERN.match(finding.endpoint):
        finding.endpoint = "unknown"
```

**Expected outcome:** No package names in endpoint field. Library gRPC code excluded from analysis.

---

## Task 4: Manifest Analyzer — Post-Process Known Permission Classifications

**Problem:** The 7B model marks INTERNET as dangerous despite the prompt listing it as NORMAL. The model's classification is unreliable for well-known permissions.

**File:** `src/apk_re/agents/manifest_analyzer/server.py`

**Fixes:**

### 4a. Post-process with hardcoded permission map
Don't trust the LLM for well-known permission classifications. Override after the fact:
```python
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

# After LLM returns findings:
for perm in findings.permissions:
    if perm.name in KNOWN_NORMAL_PERMISSIONS:
        perm.dangerous = False
    elif perm.name in KNOWN_DANGEROUS_PERMISSIONS:
        perm.dangerous = True
    # else: trust LLM for unknown/custom permissions
```

**Expected outcome:** INTERNET correctly classified as normal. All well-known permissions correctly classified regardless of LLM output.

---

## Task 5: Shared — Extract LIBRARY_PATH_SEGMENTS to base_agent.py

**Problem:** Three agents (code_analyzer, network_mapper, string_extractor after Task 1) each define their own copy of LIBRARY_PATH_SEGMENTS. This violates DRY.

**File:** `src/apk_re/agents/base/base_agent.py`

**Fix:** Move the canonical list to base_agent.py and import from there:
```python
LIBRARY_PATH_SEGMENTS = (
    "/io/netty/", "/okio/", "/okhttp3/", "/retrofit2/",
    "/dagger/", "/hilt_aggregated_deps/", "/androidx/",
    "/com/google/", "/com/android/", "/kotlin/", "/kotlinx/",
    "/org/apache/", "/io/reactivex/", "/com/squareup/",
    "/com/facebook/", "/com/crashlytics/", "/net/jodah/",
    "/com/braze/", "/com/airbnb/", "/exoplayer2/",
    "/io/grpc/", "/org/slf4j/", "/org/codehaus/",
    "/com/fasterxml/", "/org/bouncycastle/",
)

def is_library_path(path: str) -> bool:
    """Check if a file path belongs to a third-party library."""
    return any(seg in path for seg in LIBRARY_PATH_SEGMENTS)
```

Update imports in code_analyzer, network_mapper, and string_extractor to use `from apk_re.agents.base.base_agent import is_library_path`.

Remove the per-agent LIBRARY_PATH_SEGMENTS constants.

**Expected outcome:** Single source of truth for library filtering. Easy to add new library prefixes.

---

## Task 6: Re-run Full Pipeline and Compare

**No code changes.** Rebuild, re-run on ergatta.apk, dump findings, compare to Round 1 baseline.

**Success criteria:**
- String extractor: < 5 false positives (from ~150)
- Code analyzer: scores on 0.0-1.0, no hallucinated classes, non-empty flags
- Network mapper: no package names in endpoint field
- Manifest analyzer: INTERNET correctly classified as normal
- API extractor: no regressions (should still find gRPC endpoints)
- Report synthesizer: improved report (downstream of all above)

---

## Order of Execution

Task 5 (shared extraction) first since it affects Tasks 1-3. Then 1-4 in any order. Task 6 last.

Recommended order: 5 → 1 → 2 → 3 → 4 → 6

---

## Design Principle: Don't Trust the 7B Model for Deterministic Facts

Round 1 showed that prompt engineering alone is insufficient for a 7B model on certain tasks:
- Permission classification (INTERNET = normal) — model ignores explicit lists
- Score ranges (0.0-1.0 not percentages) — model outputs what it wants
- Field semantics (endpoint = URL) — model puts whatever fits

**Solution pattern: LLM generates, code validates.** Use post-processing to enforce constraints the LLM can't reliably follow. This is cheaper than moving to a larger model and more reliable than prompt iteration.
