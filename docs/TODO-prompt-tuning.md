# Prompt Tuning TODO

Issues observed from end-to-end testing with ergatta.apk (qwen2.5-coder:7b).

## Status: Round 2 planned (`docs/plans/2026-03-09-prompt-tuning-round2.md`)

---

## String Extractor
- **Kotlin mangled names**: ~150 false positives from name-mangled methods (e.g., `m5293surfaceColorAtElevationcq6XJ1M`, `createGuidelineFromAbsoluteRight-0680j_4`). Need regex filters for `m<digits>` prefix and `-<hash>` suffix patterns.
- **No library path filtering**: Scanning okio/Base64.java, slf4j, apache commons, androidx/compose. Need LIBRARY_PATH_SEGMENTS (same as other agents).
- **STYLEABLE getters**: 20+ `getSTYLEABLE_VECTOR_DRAWABLE_*` entries. Need pattern filter.
- **Java class paths**: `org/slf4j/impl/StaticLoggerBinder` misclassified as api_key. Need path pattern filter.
- **Library URLs**: slf4j.org, issuetracker.google.com, apache.org docs cluttering results.
- *Round 1 fixed*: Java identifiers (InterruptedException etc.) no longer appear.
- *Round 1 fixed*: Now finding real URLs (Braze, feed.fm).

## Code Analyzer
- **Scores still percentages**: 100.0 and 85.0 despite "0.0-1.0" in prompt. Need post-processing clamp (divide by 100).
- **Hallucinated class**: `com.example.MyClass` doesn't exist in the APK. Need input validation.
- **Empty flags**: Still returning empty `flags` lists. Need fallback keyword-based flag assignment.
- **Library code**: Triaging `io.grpc.okhttp.internal.ConnectionSpec`. Need `/io/grpc/` in library filter.

## Network Mapper
- **Package names in endpoint field**: `io.grpc.okhttp` appears 3 times as endpoint. Need post-processing regex validation.
- **Library code**: All findings from gRPC library internals. Need `/io/grpc/` in LIBRARY_PATH_SEGMENTS.

## Manifest Analyzer
- **INTERNET misclassified**: Marked dangerous=true. Prompt lists it as NORMAL but model ignores it. Need post-processing with hardcoded permission map.
- *Round 1 fixed*: Activities now populated (4 found).
- *Round 1 fixed*: WAKE_LOCK correctly classified.

## API Extractor
- *Round 1 fixed*: No more hallucinated commit URLs.
- *Round 1 fixed*: Found real gRPC service endpoints (ActivityLogServiceGrpc).
- **Minor**: URL format `/fm.feed/android.playersdk/v1/...` may have package name mixed in. Low priority.

## Report Synthesizer
- *Round 1 fixed*: App name detected (Seaborn App).
- **Parrots upstream errors**: Says INTERNET is dangerous (from manifest). Will auto-fix when upstream improves.
- **Generic recommendations**: Boilerplate security advice. Lower priority — fix upstream first.

## General (DRY)
- **Duplicate LIBRARY_PATH_SEGMENTS**: Three agents define their own copies. Extract to base_agent.py as shared constant + helper function.
