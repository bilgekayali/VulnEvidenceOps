"""The visual report is a deterministic view of actual synthetic consumer JSON."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.demo_evidence import EvidenceRejected, _read_json
from tools.demo_presentation import (
    NEGATIVE_EXPECTATIONS,
    SCRIPT,
    STYLE,
    render_html,
    verify_presentation,
)
from tools.doraops_demo.__main__ import run_demo


class DemoPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="veo-presentation-tests-")
        cls.root = Path(cls.temporary.name) / "evidence"
        run_demo(cls.root)
        cls.presentation = _read_json(cls.root / "presentation.json")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self, name: str) -> Path:
        target = Path(self.temporary.name) / name
        shutil.copytree(self.root, target)
        return target

    def mutate(self, name: str, relative: str, change) -> Path:
        target = self.copy(name)
        path = target / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")
        return target

    def test_machine_model_is_bound_to_real_files_and_manifest(self):
        result = verify_presentation(self.root)
        self.assertTrue(result["verified"])
        self.assertEqual(result["negative_case_count"], 14)
        self.assertEqual(result["scenario_count"], 4)
        self.assertEqual(self.presentation["duration_minutes"], 5)
        self.assertEqual(
            [item["system"] for item in self.presentation["signature_scopes"]],
            ["DataGovOps", "DORAOps"],
        )
        self.assertTrue(all(item["verified"] for item in self.presentation["signature_scopes"]))
        self.assertEqual(self.presentation["risk"]["inherent_score"], 9)
        self.assertEqual(self.presentation["risk"]["residual_score"], 9)
        self.assertEqual(self.presentation["risk"]["control_credit"], 0)
        self.assertTrue(self.presentation["risk"]["remediation_required"])
        self.assertEqual(
            {item["id"]: item["error_code"] for item in self.presentation["negative_cases"]},
            NEGATIVE_EXPECTATIONS,
        )
        links = [self.presentation["environment"]["evidence"]]
        for scope in self.presentation["signature_scopes"]:
            links.extend((scope["receipt"], scope["verification"]))
        links.append(self.presentation["risk"]["decision"])
        for scenario in self.presentation["scenarios"]:
            links.extend(scenario["evidence"])
        links.extend(item["evidence"] for item in self.presentation["negative_cases"])
        for link in links:
            with self.subTest(path=link["path"]):
                path = self.root / link["path"]
                raw = path.read_bytes()
                self.assertTrue(path.is_file())
                self.assertEqual(link["size_bytes"], len(raw))
                self.assertEqual(link["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertNotIn("..", Path(link["path"]).parts)
        artifacts = {
            item["path"] for item in _read_json(self.root / "manifest.json")["artifacts"]
        }
        self.assertIn("index.html", artifacts)
        self.assertIn("presentation.json", artifacts)

    def test_html_is_self_contained_csp_locked_and_accessible(self):
        rendered = (self.root / "index.html").read_text(encoding="utf-8")
        style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
        script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
        self.assertIn(f"style-src &#x27;sha256-{style_hash}&#x27;", rendered)
        self.assertIn(f"script-src &#x27;sha256-{script_hash}&#x27;", rendered)
        self.assertNotRegex(
            rendered,
            re.compile(r"https?://|//[A-Za-z0-9]|fetch\s*\(|XMLHttpRequest|WebSocket"),
        )
        self.assertIn('class="skip-link"', rendered)
        self.assertIn('aria-label="Filter outcome cards"', rendered)
        self.assertEqual(rendered.count('data-filter="'), 4)
        self.assertIn('aria-live="polite"', rendered)
        self.assertIn("Finding closure does not automatically reduce risk.", rendered)
        self.assertIn("Fourteen required rejection boundaries", rendered)
        match = re.search(
            r'<script id="presentation-data" type="application/json">(.*?)</script>',
            rendered,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        self.assertEqual(json.loads(match.group(1)), self.presentation)

    def test_positive_and_attention_claim_tampering_fails_closed(self):
        cases = (
            (
                "risk",
                "doraops/consumer/risk-decision.json",
                lambda value: value.__setitem__("residual_score", 8),
            ),
            (
                "signature",
                "doraops/consumer/signature-verification.json",
                lambda value: value.__setitem__("signature_valid", False),
            ),
            (
                "attention",
                "attention/missing-retest/consumer/receipt.json",
                lambda value: value.__setitem__("resolution_state", "successful"),
            ),
            (
                "audience",
                "datagovops/consumer/key-policy.json",
                lambda value: value.__setitem__("audience", "another-consumer"),
            ),
        )
        for name, relative, change in cases:
            with self.subTest(name=name):
                target = self.mutate("tampered-" + name, relative, change)
                with self.assertRaises(EvidenceRejected):
                    verify_presentation(target)

    def test_negative_code_model_html_and_source_tampering_fail_closed(self):
        target = self.mutate(
            "tampered-negative",
            "negative/rehashed-completion/rejection.json",
            lambda value: value.__setitem__("error_code", "accepted"),
        )
        with self.assertRaises(EvidenceRejected):
            verify_presentation(target)

        target = self.mutate(
            "tampered-model",
            "presentation.json",
            lambda value: value["risk"].__setitem__("control_credit", 1),
        )
        with self.assertRaises(EvidenceRejected):
            verify_presentation(target)

        target = self.copy("tampered-html")
        with (target / "index.html").open("a", encoding="utf-8") as stream:
            stream.write("<!-- changed -->")
        with self.assertRaises(EvidenceRejected):
            verify_presentation(target)

        target = self.mutate(
            "tampered-source",
            "source-provenance.json",
            lambda value: value.__setitem__("commit_sha", "not-a-sha"),
        )
        with self.assertRaises(EvidenceRejected):
            verify_presentation(target)

    def test_missing_or_unsafe_linked_evidence_fails_closed(self):
        target = self.copy("missing-evidence")
        (target / "doraops/consumer/risk-decision.json").unlink()
        with self.assertRaises(EvidenceRejected):
            verify_presentation(target)

        target = self.mutate(
            "unsafe-link",
            "presentation.json",
            lambda value: value["risk"]["decision"].__setitem__("path", "../outside.json"),
        )
        with self.assertRaises(EvidenceRejected):
            verify_presentation(target)

    def test_renderer_escapes_markup_in_text_and_embedded_json(self):
        value = copy.deepcopy(self.presentation)
        value["title"] = '</title><img src=x onerror="alert(1)">'
        rendered = render_html(value)
        self.assertNotIn("<img src=x", rendered)
        self.assertIn("&lt;/title&gt;&lt;img", rendered)
        self.assertIn("\\u003c/title\\u003e\\u003cimg", rendered)


if __name__ == "__main__":
    unittest.main()
