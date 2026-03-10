import json
import textwrap
from pathlib import Path

from apk_re.agents.string_extractor.server import (
    _is_false_positive_string,
    create_string_extractor_server,
    extract_strings_from_file,
    shannon_entropy,
)


# --- Entropy tests ---


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_single_char():
    assert shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_high_entropy():
    # Random-looking string should have high entropy
    ent = shannon_entropy("aB3$xZ9!mK7@pQ2&")
    assert ent > 3.5


def test_shannon_entropy_low_entropy():
    ent = shannon_entropy("aaaaabbbbb")
    assert ent < 2.0


# --- Server tool registration ---


def test_server_has_extract_strings_tool():
    server = create_string_extractor_server()
    assert "extract_strings" in server._tool_manager._tools


def test_server_has_read_file_tool():
    server = create_string_extractor_server()
    assert "read_file" in server._tool_manager._tools


# --- Regex extraction ---


def test_extract_urls(tmp_path):
    java_file = tmp_path / "Test.java"
    java_file.write_text(textwrap.dedent("""\
        public class Test {
            String api = "https://api.example.com/v1/users";
            String internal = "http://10.0.0.1:8080/debug";
        }
    """))
    findings = extract_strings_from_file(java_file)
    urls = [f for f in findings if f.category == "url"]
    values = [f.value for f in urls]
    assert "https://api.example.com/v1/users" in values
    assert "http://10.0.0.1:8080/debug" in values


def test_extract_api_keys(tmp_path):
    java_file = tmp_path / "Keys.java"
    java_file.write_text(textwrap.dedent("""\
        public class Keys {
            String googleKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
            String awsKey = "AKIAIOSFODNN7EXAMPLE";
            String openaiKey = "sk-proj1234567890abcdefghijklmnopqrst";
        }
    """))
    findings = extract_strings_from_file(java_file)
    api_keys = [f for f in findings if f.category == "api_key"]
    values = [f.value for f in api_keys]
    assert any(v.startswith("AIza") for v in values)
    assert any(v.startswith("AKIA") for v in values)
    assert any(v.startswith("sk-") for v in values)


def test_extract_jwt_token(tmp_path):
    java_file = tmp_path / "Auth.java"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    java_file.write_text(f'public class Auth {{ String t = "{jwt}"; }}\n')
    findings = extract_strings_from_file(java_file)
    tokens = [f for f in findings if f.category == "token"]
    assert len(tokens) >= 1
    assert tokens[0].value.startswith("eyJ")


def test_extract_base64_blob(tmp_path):
    java_file = tmp_path / "Blob.java"
    # A base64-like string with high entropy
    b64 = "dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5n"
    java_file.write_text(f'public class Blob {{ String b = "{b64}"; }}\n')
    findings = extract_strings_from_file(java_file)
    blobs = [f for f in findings if f.category == "encoded_blob"]
    assert len(blobs) >= 1


# --- False positive filtering ---


def test_filters_android_schema_urls(tmp_path):
    java_file = tmp_path / "Schema.java"
    java_file.write_text(textwrap.dedent("""\
        public class Schema {
            String ns = "http://schemas.android.com/apk/res/android";
            String w3 = "http://www.w3.org/2001/XMLSchema";
        }
    """))
    findings = extract_strings_from_file(java_file)
    urls = [f for f in findings if f.category == "url"]
    assert len(urls) == 0


def test_filters_package_names(tmp_path):
    java_file = tmp_path / "Pkg.java"
    # Package names shouldn't show up as encoded_blob or api_key
    java_file.write_text(textwrap.dedent("""\
        public class Pkg {
            String pkg = "com.android.providers.contacts";
            String pkg2 = "com.google.android.gms.location";
        }
    """))
    findings = extract_strings_from_file(java_file)
    # Should have no api_key or encoded_blob findings for package names
    non_url = [f for f in findings if f.category in ("api_key", "encoded_blob")]
    assert len(non_url) == 0


def test_line_numbers_are_set(tmp_path):
    java_file = tmp_path / "Lines.java"
    java_file.write_text(textwrap.dedent("""\
        // line 1
        // line 2
        public class Lines {
            String u = "https://api.example.com/secret";
        }
    """))
    findings = extract_strings_from_file(java_file)
    assert len(findings) >= 1
    assert findings[0].line_number == 4


def test_entropy_is_populated(tmp_path):
    java_file = tmp_path / "Ent.java"
    java_file.write_text('public class Ent { String u = "https://api.example.com"; }\n')
    findings = extract_strings_from_file(java_file)
    assert len(findings) >= 1
    assert findings[0].entropy is not None
    assert findings[0].entropy > 0


def test_extract_strings_tool_nonexistent_dir(tmp_path):
    """The tool should return an error JSON when directory doesn't exist."""
    server = create_string_extractor_server()
    tool_fn = server._tool_manager._tools["extract_strings"].fn
    result = tool_fn(source_dir=str(tmp_path / "nonexistent"))
    parsed = json.loads(result)
    assert "error" in parsed


def test_extract_strings_tool_integration(tmp_path):
    """End-to-end test using the tool function."""
    src = tmp_path / "src"
    src.mkdir()
    java_file = src / "App.java"
    java_file.write_text(textwrap.dedent("""\
        public class App {
            String api = "https://api.secret-service.com/v2/data";
            String key = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
        }
    """))
    server = create_string_extractor_server()
    tool_fn = server._tool_manager._tools["extract_strings"].fn
    result = tool_fn(source_dir=str(src))
    parsed = json.loads(result)
    assert isinstance(parsed, list)
    assert len(parsed) >= 2
    categories = {f["category"] for f in parsed}
    assert "url" in categories
    assert "api_key" in categories


def test_skips_large_files(tmp_path):
    """Files over 1MB should be skipped."""
    java_file = tmp_path / "Huge.java"
    # Write a file just over 1MB
    java_file.write_text("// " + "x" * 1_100_000 + "\n")
    server = create_string_extractor_server()
    tool_fn = server._tool_manager._tools["extract_strings"].fn
    result = tool_fn(source_dir=str(tmp_path))
    parsed = json.loads(result)
    assert parsed == []


# --- False positive: camelCase and PascalCase identifiers ---


def test_filters_camelcase_identifiers():
    """camelCase Java identifiers should be filtered as false positives."""
    assert _is_false_positive_string("InterruptedException") is True
    assert _is_false_positive_string("checkNotNullParameter") is True
    assert _is_false_positive_string("onOTAMCBFirmwareUpdateStatus") is True


def test_filters_pascalcase_java_suffixes():
    """PascalCase names ending with Java suffixes should be filtered."""
    assert _is_false_positive_string("HiltViewModelFactory") is True
    assert _is_false_positive_string("FragmentComponentBuilderEntryPoint") is True
    assert _is_false_positive_string("AbstractQueuedSynchronizer") is True


def test_filters_jvm_type_descriptors():
    """JVM internal type descriptors (L-prefixed paths) should be filtered."""
    assert _is_false_positive_string("Ljava/security/MessageDigest") is True
    assert _is_false_positive_string("Landroid/os/Bundle") is True
    assert _is_false_positive_string("Lkotlin/jvm/internal/Intrinsics") is True


def test_real_base64_with_digits_detected(tmp_path):
    """Real base64 strings containing digits should still be detected."""
    java_file = tmp_path / "Secret.java"
    # A high-entropy base64 string with digits
    b64 = "dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5n"
    java_file.write_text(f'public class Secret {{ String s = "{b64}"; }}\n')
    findings = extract_strings_from_file(java_file)
    blobs = [f for f in findings if f.category == "encoded_blob"]
    assert len(blobs) >= 1


def test_deduplication(tmp_path):
    """Same value appearing in multiple files should only be reported once."""
    src = tmp_path / "src"
    src.mkdir()
    for name in ("A.java", "B.java"):
        f = src / name
        f.write_text('public class X { String u = "https://api.example.com/v1/dup"; }\n')
    server = create_string_extractor_server()
    tool_fn = server._tool_manager._tools["extract_strings"].fn
    result = tool_fn(source_dir=str(src))
    parsed = json.loads(result)
    dup_values = [f["value"] for f in parsed if f["value"] == "https://api.example.com/v1/dup"]
    assert len(dup_values) == 1


def test_pure_letter_strings_not_detected_as_base64(tmp_path):
    """Pure-letter strings (no digits, no +/=) should not be flagged as encoded_blob."""
    java_file = tmp_path / "Ident.java"
    # These are pure-letter strings that previously matched as base64
    java_file.write_text(textwrap.dedent("""\
        public class Ident {
            String a = "InterruptedException";
            String b = "checkNotNullParameter";
            String c = "AbstractQueuedSynchronizer";
        }
    """))
    findings = extract_strings_from_file(java_file)
    blobs = [f for f in findings if f.category == "encoded_blob"]
    assert len(blobs) == 0
