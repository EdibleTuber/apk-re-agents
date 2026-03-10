# Prompt Tuning Plan — Round 1

**Goal:** Reduce false positives and improve signal quality across all agents so the pipeline produces actionable findings on the ergatta.apk test case. We'll iterate on this same APK until the output is genuinely useful, then validate against a fresh APK.

**Approach:** Fix the noisiest agents first. Each fix is tested by re-running the full pipeline and comparing output against the current baseline (`findings_dump.txt`).

**Test loop:** After each task, rebuild and re-run on ergatta.apk. Compare to baseline. If the output improved, commit. If not, iterate.

---

## Task 1: String Extractor — Kill the False Positives

**Problem:** 100% of findings are Java/Kotlin identifiers (`InterruptedException`, `checkNotNullParameter`, `HiltViewModelFactory`). The base64 pattern matches camelCase names because they're 20+ alphanumeric chars with entropy > 3.5. Zero actual secrets found.

**File:** `src/apk_re/agents/string_extractor/server.py`

**Fixes:**
1. **Filter camelCase/PascalCase identifiers** — if a string matches `^[a-z][a-zA-Z0-9]+$` or `^[A-Z][a-zA-Z]+[a-z][a-zA-Z]*$` (mixed case with no separators), it's a Java identifier, not a secret. Real base64 has mixed case + digits + `/+=` without the structured casing of identifiers.
2. **Filter common Java suffixes** — strings ending in `Exception`, `Handler`, `Listener`, `Factory`, `Module`, `Component`, `Service`, `EntryPoint`, `Wrapper`, `Parameter`, etc.
3. **Filter JVM type descriptors** — strings starting with `L` followed by a path (`Ljava/`, `Lokio/`, `Landroid/`)
4. **Raise base64 entropy threshold** — from 3.5 to 4.5. Real base64 encoded data has high entropy. Java identifiers sit in the 3.5-4.2 range.
5. **Require base64 charset** — real base64 contains digits and `+/=`. Add a check: string must contain at least one digit or `+/=` character to qualify as encoded_blob.
6. **Deduplicate** — same value appearing on multiple lines should be reported once (first occurrence)

**Expected outcome:** Near-zero false positives. May find zero secrets in ergatta.apk (which is a valid result — not every app has hardcoded secrets). Quality over quantity.

**Tests:** Update existing tests. Add test cases for camelCase filtering.

---

## Task 2: Code Analyzer — Fix Scoring Scale and Add Flag Examples

**Problem:** Relevance scores are 100.0/95.0/90.0 instead of 0.0-1.0. Flags are empty. Only 3 classes triaged.

**File:** `src/apk_re/agents/code_analyzer/server.py`

**Fixes:**
1. **Scoring scale in prompt** — add explicit instruction: "Scores MUST be between 0.0 and 1.0. Do NOT use percentages. Example: 0.7, not 70."
2. **Flag examples in prompt** — add concrete examples:
   ```
   flags examples:
   - ["network"] for classes using HTTP clients, sockets, or URL connections
   - ["crypto"] for classes using Cipher, MessageDigest, KeyStore, SecretKey
   - ["storage"] for classes using SharedPreferences, SQLite, file I/O
   - ["auth"] for classes handling login, tokens, passwords, sessions
   - ["webview"] for classes using WebView, JavascriptInterface
   - ["ipc"] for classes using Intent, BroadcastReceiver, ContentProvider
   ```
3. **Pre-filter keywords** — review if the keyword list is catching enough files. The app has ifit/glassos/ergatta packages that should be prioritized over library code. Consider excluding common library packages from triage (okio, netty, dagger, hilt, firebase, exoplayer, kotlin, androidx).

**Expected outcome:** Scores on 0.0-1.0 scale, non-empty flags, more app-specific classes triaged.

---

## Task 3: API Extractor — Find Real Endpoints, Not Source URLs

**Problem:** Found commit URLs from comments, not runtime API endpoints. Hallucinated commit hashes.

**File:** `src/apk_re/agents/api_extractor/server.py`

**Fixes:**
1. **Prompt rewrite** — add explicit negative examples:
   ```
   DO NOT extract:
   - URLs from comments, license headers, or source code references
   - Repository/commit URLs (github.com, gitlab.com, bitbucket.org, etc.)
   - Documentation URLs

   DO extract:
   - Base URLs the app connects to at runtime (e.g., "https://api.example.com/v1/")
   - Retrofit @GET/@POST path annotations (e.g., @GET("users/{id}"))
   - URLs constructed in HTTP client code (OkHttp Request.Builder, HttpURLConnection)

   IMPORTANT: Only extract URLs that appear VERBATIM in the code. Do not fabricate or modify URLs.
   ```
2. **Pre-filter improvement** — exclude files from common library packages (same as code analyzer). Focus on app-specific code where API definitions live.
3. **Post-filter** — in the tool code (not the prompt), filter out URLs matching known non-API patterns: `github.com`, `gitlab.com`, `bitbucket.org`, `sources.gett.com`, any URL containing `/commit/`.

**Expected outcome:** Either real API endpoints from the app's own code, or an empty result (which is honest).

---

## Task 4: Network Mapper — Fix Endpoint Field and Deduplicate

**Problem:** `endpoint` field contains class names (`OpenSslX509TrustManagerWrapper`) instead of URLs. Duplicate findings for the same class.

**File:** `src/apk_re/agents/network_mapper/server.py`

**Fixes:**
1. **Prompt clarification** — add:
   ```
   IMPORTANT: The "endpoint" field must contain a URL, hostname, or IP address — NOT a class name.
   If a class handles network traffic but you cannot identify the specific endpoint URL, use "unknown" as the endpoint value.
   The "source_class" field is where the class name goes.
   ```
2. **Deduplication** — add post-processing to deduplicate findings with the same endpoint + source_class.
3. **Library filtering** — exclude common library packages from analysis (netty internals, okhttp internals, etc.). Focus on app-specific network code.

**Expected outcome:** Findings with actual endpoint URLs (or "unknown"), correct field usage, no duplicates.

---

## Task 5: Manifest Analyzer — Extract Activities and Fix WAKE_LOCK

**Problem:** Found 0 activities (ergatta definitely has activities). WAKE_LOCK was misclassified in earlier run.

**File:** `src/apk_re/agents/manifest_analyzer/server.py`

**Fixes:**
1. **Add WAKE_LOCK and RECEIVE_BOOT_COMPLETED** to the explicit normal permissions list in the prompt
2. **Emphasize activity extraction** — add: "Extract ALL activities declared in the manifest, including the main launcher activity. Activities are critical for understanding the app's entry points."

**Expected outcome:** Activities populated, WAKE_LOCK correctly classified as normal.

---

## Task 6: Cross-Agent — Exclude Library Code

**Problem:** Multiple agents waste LLM calls on third-party library code (netty, okio, hilt, dagger, firebase, exoplayer, kotlin stdlib) instead of the app's own code.

**Files:** All LLM-powered agent server.py files

**Fix:** Add a shared list of library package prefixes to exclude from file scanning:
```python
LIBRARY_PREFIXES = (
    "io/netty/", "okio/", "okhttp3/", "retrofit2/",
    "dagger/", "hilt_aggregated_deps/", "androidx/",
    "com/google/", "com/android/", "kotlin/", "kotlinx/",
    "org/apache/", "io/reactivex/", "com/squareup/",
    "com/facebook/", "com/crashlytics/", "net/jodah/",
)
```
This could live in `base_agent.py` as a shared constant, or each agent can have its own version tuned to what it cares about.

**Expected outcome:** LLM calls focus on app-specific code (com/ifit/, ergatta packages), producing more relevant findings.

---

## Task 7: Re-run Full Pipeline and Compare

**No code changes.** Rebuild, re-run on ergatta.apk, dump findings, compare to baseline.

**Success criteria:**
- String extractor: < 10% false positive rate (ideally 0)
- Code analyzer: scores on 0.0-1.0 scale, non-empty flags
- API extractor: no hallucinated URLs, only real endpoints (or empty)
- Network mapper: endpoint field has URLs not class names
- Manifest analyzer: activities populated
- Report synthesizer: improved report quality (downstream of all above)

---

## Order of Execution

Tasks 1-5 can mostly be done independently. Task 6 (library filtering) touches multiple agents so do it last. Task 7 is the validation run.

Recommended order: 1 → 2 → 3 → 4 → 5 → 6 → 7

After Task 7, if results are good, try a second APK to validate generalization.
