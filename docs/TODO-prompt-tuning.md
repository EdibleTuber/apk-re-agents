# Prompt Tuning TODO

Issues observed from end-to-end testing with ergatta.apk (qwen2.5-coder:7b).

## Network Mapper
- **Duplicate findings**: Same file (OpenSslX509TrustManagerWrapper) analyzed multiple times, producing near-identical findings. Need to deduplicate in the prompt or post-process results.
- **Endpoint field misuse**: The `endpoint` field contains class names instead of actual network endpoints/URLs. Prompt should clarify that `endpoint` means the URL or host being connected to, not the class name.

## Code Analyzer
- **Empty flags**: LLM returns empty `flags` lists despite analyzing security-relevant classes (HttpClient, CachedContentIndex). Prompt should give concrete examples of when to use each flag category.
- **Missing relevance context**: Triage found only 2 classes — the pre-filter keywords or batch size may need tuning to catch more relevant code.

## Manifest Analyzer
- **WAKE_LOCK misclassified**: Flagged as dangerous (it's a normal permission). Add WAKE_LOCK to the explicit normal permissions list in the prompt.

## General
- **Result deduplication**: Multiple agents may benefit from a post-processing step to deduplicate similar findings before writing to disk.
- **Batch prompt clarity**: When sending multiple files in one prompt, the LLM sometimes conflates findings across files. Consider clearer file delimiters in the prompt.

## Report Synthesizer
- **Untested**: First agent using the 32b model. May need prompt adjustments once tested end-to-end.
- **Context window**: Total findings may exceed the model's context. Current truncation is per-section (3000 chars) + total (12000 chars). May need tuning based on real outputs.
