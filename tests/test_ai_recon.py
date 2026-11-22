"""Unit tests for AI RECON (stdlib unittest; no network, no extra deps).

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from airecon.core.detect import (identify_platform, scan_headers, scan_tech,
                                 find_public_api_hosts, classify_endpoint_status)
from airecon.core.findings import Confidence, Finding, Findings
from airecon.core.report import render_markdown
from airecon.core.scope import Mode, Scope, ScopeError


class TestScope(unittest.TestCase):
    def test_active_fails_closed_without_allow(self):
        s = Scope()
        allowed, _ = s.check("https://example.com")
        self.assertFalse(allowed)
        with self.assertRaises(ScopeError):
            s.authorize("https://example.com")

    def test_passive_allowed_for_public_host(self):
        s = Scope()
        d = s.decide("https://chatgpt.com", Mode.PASSIVE)
        self.assertTrue(d.allowed, d.reason)

    def test_active_allowed_when_listed(self):
        s = Scope(allow=["example.com"])
        self.assertTrue(s.decide("https://example.com/x", Mode.ACTIVE).allowed)

    def test_glob_and_cidr(self):
        s = Scope(allow=["*.example.com", "10.0.0.0/24"])
        self.assertTrue(s.decide("https://api.example.com", Mode.ACTIVE).allowed)
        self.assertTrue(s.decide("http://10.0.0.7", Mode.ACTIVE).allowed)
        self.assertFalse(s.decide("http://10.0.1.7", Mode.ACTIVE).allowed)

    def test_deny_always_wins(self):
        s = Scope(allow=["example.com"], deny=["example.com"])
        self.assertFalse(s.decide("https://example.com", Mode.PASSIVE).allowed)
        self.assertFalse(s.decide("https://example.com", Mode.ACTIVE).allowed)

    def test_allow_private(self):
        s = Scope(allow_private=True)
        self.assertTrue(s.decide("http://127.0.0.1:8770", Mode.ACTIVE).allowed)

    def test_scope_from_hostlist_file(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# comment\n127.0.0.1\napi.example.com\n")
            p = f.name
        try:
            s = Scope.from_file(p)
            self.assertIn("127.0.0.1", s.allow)
            self.assertIn("api.example.com", s.allow)
        finally:
            os.unlink(p)

    def test_scope_from_yaml_file(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("allow:\n  - target.test\nnote: engagement\n")
            p = f.name
        try:
            s = Scope.from_file(p)
            self.assertTrue(s.decide("https://target.test", Mode.ACTIVE).allowed)
        finally:
            os.unlink(p)

    def test_yaml_with_leading_comments_keeps_deny(self):
        # regression: a comment-first YAML file must NOT be parsed as a host
        # list, or its `deny:` values would be misread as allow entries.
        import tempfile, os
        content = (
            "# engagement scope\n"
            "# owner: Jane\n"
            "\n"
            "allow:\n"
            "  - target.test\n"
            "deny:\n"
            "  - forbidden.test\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(content)
            p = f.name
        try:
            s = Scope.from_file(p)
            self.assertIn("target.test", s.allow)
            self.assertIn("forbidden.test", s.deny)
            self.assertTrue(s.decide("https://target.test", Mode.ACTIVE).allowed)
            # deny must win even in passive mode
            self.assertFalse(s.decide("https://forbidden.test", Mode.PASSIVE).allowed)
        finally:
            os.unlink(p)

    def test_host_list_file_still_works(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# only a list here\nweb.test\napi.test\n")
            p = f.name
        try:
            s = Scope.from_file(p)
            self.assertIn("web.test", s.allow)
            self.assertIn("api.test", s.allow)
            self.assertEqual(s.deny, [])
        finally:
            os.unlink(p)

    def test_malformed_yaml_raises_instead_of_falling_back(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("allow: [unclosed\n")
            p = f.name
        try:
            with self.assertRaises(ScopeError):
                Scope.from_file(p)
        finally:
            os.unlink(p)


class TestPlatformDetection(unittest.TestCase):
    def test_openai_from_unique_header(self):
        v = identify_platform({"X-OpenAI-Proxy-Wasm": "v0.1",
                               "Server": "cloudflare"})
        self.assertEqual(v.platform, "OpenAI / ChatGPT")
        self.assertEqual(v.confidence, "confirmed")

    def test_gemini_from_esf_server(self):
        v = identify_platform({"Server": "ESF"})
        self.assertEqual(v.platform, "Google Gemini")
        self.assertEqual(v.confidence, "confirmed")

    def test_huggingface_from_xpoweredby(self):
        v = identify_platform({"X-Powered-By": "huggingface-moon"})
        self.assertEqual(v.platform, "Hugging Face")

    def test_no_false_positive_on_generic_site(self):
        v = identify_platform({"Server": "nginx"}, "<html>hello world</html>")
        self.assertIsNone(v.platform)

    def test_no_false_positive_on_bare_brand_word(self):
        # a single weak body mention alone must not claim a platform
        v = identify_platform({}, "we talked about claude yesterday")
        self.assertIsNone(v.platform)


class TestDetection(unittest.TestCase):
    def test_chroma_css_is_not_a_vector_db(self):
        # regression: CSS custom property must not look like ChromaDB
        body = ":root { --content-chromatic-channels: clamp(0, l, 1) }"
        comps = {m.component for m in scan_tech({}, body)}
        self.assertNotIn("ChromaDB", comps)

    def test_header_fingerprint_nginx(self):
        comps = {m.component for m in scan_headers({"Server": "nginx"})}
        self.assertIn("nginx", comps)

    def test_classify_endpoint_status(self):
        self.assertEqual(classify_endpoint_status(401), "exists_protected")
        self.assertEqual(classify_endpoint_status(404), "not_found")
        self.assertEqual(classify_endpoint_status(200), "exists_open")

    def test_public_api_host_extraction(self):
        body = 'fetch("https://api.example.com/v1") and https://inference.foo.ai/x'
        hosts = find_public_api_hosts(body)
        self.assertIn("api.example.com", hosts)


class TestFindingsAndReport(unittest.TestCase):
    def test_confidence_buckets(self):
        fs = Findings()
        fs.add(Finding(module="m", title="a", confidence=Confidence.CONFIRMED))
        fs.add(Finding(module="m", title="b", confidence=Confidence.INFO))
        self.assertEqual(len(fs.by_confidence(Confidence.CONFIRMED)), 1)
        self.assertEqual(len(fs.by_confidence(Confidence.INFO)), 2)

    def test_report_has_limitations_and_kinds(self):
        fs = Findings()
        fs.add(Finding(module="passive/headers", title="Test obs",
                       confidence=Confidence.INFO))
        md = render_markdown("https://t.test", fs,
                             not_tested=["authenticated surfaces"])
        self.assertIn("Not tested", md)
        self.assertIn("Observations", md)
        self.assertIn("Test obs", md)


if __name__ == "__main__":
    unittest.main()
