# ruff: noqa: E501
"""Create and verify a self-contained, evidence-linked portfolio presentation.

Every displayed outcome is derived from bounded JSON files produced by the real
demo consumers. The verifier rebuilds both the presentation model and HTML, so a
changed claim, evidence link, CSP, or rendered value fails closed.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from pathlib import Path

from tools.demo_evidence import (
    MAX_FILE_BYTES,
    EvidenceRejected,
    _hex,
    _json_bytes,
    _path,
    _read_bytes,
    _read_json,
)

SCHEMA_VERSION = "vulnevidenceops.portfolio-presentation.v1"
TITLE = "From synthetic finding to defensible closure"
NARRATIVE = "VulnEvidenceOps → DataGovOps → DORAOps"

NEGATIVE_EXPECTATIONS = {
    "modified-input": "input_digest_mismatch",
    "incompatible-schema": "schema_incompatible",
    "wrong-operational-boundary": "boundary_mismatch",
    "forged-datagovops-receipt": "upstream_receipt_mismatch",
    "plan-is-not-completion": "schema_incompatible",
    "wrong-independent-reviewer": "doraops_rejected",
    "retest-before-completion": "doraops_rejected",
    "unsigned-doraops-input": "doraops_signature_required",
    "wrong-signature-audience": "doraops_signature_context_mismatch",
    "wrong-signing-key": "doraops_signature_invalid",
    "untrusted-signing-key": "doraops_key_not_trusted",
    "revoked-signing-key": "doraops_key_revoked",
    "rehashed-completion": "doraops_signature_invalid",
    "upstream-signature-replay": "doraops_signature_context_mismatch",
}

STYLE = r"""
:root {
  color-scheme: light dark;
  --bg: #f5f7f2;
  --surface: #ffffff;
  --surface-2: #edf3ee;
  --ink: #11261f;
  --muted: #587067;
  --line: #cbd8d0;
  --teal: #087f6c;
  --teal-dark: #04594c;
  --lime: #c7f464;
  --amber: #a86400;
  --red: #b42318;
  --shadow: 0 18px 48px rgba(17, 38, 31, .10);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(circle at 85% -10%, rgba(199, 244, 100, .30), transparent 35rem),
    var(--bg);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.55;
}
a { color: var(--teal-dark); text-underline-offset: .18em; }
a:hover { text-decoration-thickness: .14em; }
a:focus-visible, button:focus-visible, summary:focus-visible {
  outline: 3px solid var(--teal);
  outline-offset: 3px;
}
.skip-link {
  position: fixed;
  left: 1rem;
  top: -5rem;
  z-index: 20;
  padding: .75rem 1rem;
  background: var(--surface);
  border: 2px solid var(--teal);
  border-radius: .5rem;
}
.skip-link:focus { top: 1rem; }
.shell { width: min(1120px, calc(100% - 2rem)); margin: 0 auto; }
.hero { padding: clamp(3rem, 8vw, 7rem) 0 2.5rem; }
.eyebrow {
  display: inline-flex;
  gap: .45rem;
  align-items: center;
  margin: 0 0 1.25rem;
  color: var(--teal-dark);
  font-size: .78rem;
  font-weight: 800;
  letter-spacing: .14em;
  text-transform: uppercase;
}
.eyebrow::before { content: ""; width: 2rem; height: .25rem; background: var(--lime); }
h1, h2, h3, p { margin-top: 0; }
h1 {
  max-width: 13ch;
  margin-bottom: 1.25rem;
  font-size: clamp(2.6rem, 7vw, 5.8rem);
  line-height: .98;
  letter-spacing: -.055em;
}
h2 { margin-bottom: 1rem; font-size: clamp(1.65rem, 3.4vw, 2.65rem); letter-spacing: -.03em; }
h3 { margin-bottom: .5rem; font-size: 1.08rem; }
.lede { max-width: 68ch; color: var(--muted); font-size: clamp(1.05rem, 2vw, 1.28rem); }
.hero-meta, .metric-grid, .scope-grid, .scenario-grid, .nonclaim-grid {
  display: grid;
  gap: 1rem;
}
.hero-meta { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 2rem; }
.meta-card, .scope-card, .scenario, .metric, .nonclaim {
  border: 1px solid var(--line);
  border-radius: 1rem;
  background: color-mix(in srgb, var(--surface) 94%, transparent);
  box-shadow: var(--shadow);
}
.meta-card { padding: 1.15rem; }
.label { color: var(--muted); font-size: .72rem; font-weight: 800; letter-spacing: .11em; text-transform: uppercase; }
code { overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .84em; }
.section { padding: clamp(2.5rem, 6vw, 5rem) 0; border-top: 1px solid var(--line); }
.section-copy { max-width: 70ch; color: var(--muted); }
.pipeline {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: .75rem;
  margin: 2rem 0 0;
  padding: 0;
  list-style: none;
  counter-reset: stage;
}
.pipeline li {
  position: relative;
  min-height: 10rem;
  padding: 3.2rem 1rem 1rem;
  border-top: .35rem solid var(--teal);
  border-radius: .35rem .35rem 1rem 1rem;
  background: var(--surface);
  box-shadow: var(--shadow);
  counter-increment: stage;
}
.pipeline li::before {
  content: "0" counter(stage);
  position: absolute;
  top: .9rem;
  color: var(--teal);
  font-size: .8rem;
  font-weight: 900;
  letter-spacing: .08em;
}
.pipeline strong { display: block; margin-bottom: .45rem; }
.pipeline span { color: var(--muted); font-size: .9rem; }
.scope-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.scope-card { padding: 1.35rem; }
.scope-head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }
.badge {
  display: inline-flex;
  align-items: center;
  min-height: 1.8rem;
  padding: .25rem .65rem;
  border-radius: 999px;
  background: var(--lime);
  color: #173008;
  font-size: .75rem;
  font-weight: 900;
  letter-spacing: .04em;
  text-transform: uppercase;
}
.scope-value { margin: 1rem 0; padding: .85rem; border-radius: .65rem; background: var(--surface-2); }
.scope-value span { display: block; color: var(--muted); font-size: .75rem; }
.scope-value code { display: block; margin-top: .2rem; }
.evidence-links { display: flex; flex-wrap: wrap; gap: .5rem 1rem; font-size: .88rem; }
.callout {
  margin: 2rem 0;
  padding: clamp(1.4rem, 4vw, 2.2rem);
  border-left: .6rem solid var(--amber);
  border-radius: .5rem 1rem 1rem .5rem;
  background: #fff3d6;
  color: #412900;
}
.callout strong { display: block; font-size: clamp(1.35rem, 3vw, 2rem); letter-spacing: -.025em; }
.metric-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.metric { padding: 1.2rem; box-shadow: none; }
.metric-value { display: block; margin-top: .25rem; font-size: 2rem; font-weight: 850; letter-spacing: -.04em; }
.metric small { display: block; margin-top: .35rem; color: var(--muted); }
.filters { display: flex; flex-wrap: wrap; gap: .55rem; margin: 1.4rem 0; }
.filters button {
  min-height: 2.65rem;
  padding: .55rem .95rem;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--surface);
  color: var(--ink);
  cursor: pointer;
  font: inherit;
  font-weight: 750;
}
.filters button[aria-pressed="true"] { border-color: var(--teal); background: var(--teal); color: #fff; }
.scenario-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.scenario { position: relative; padding: 1.35rem; overflow: hidden; }
.scenario::after { content: ""; position: absolute; inset: 0 auto 0 0; width: .35rem; background: var(--teal); }
.scenario[data-outcome="blocked"]::after { background: var(--amber); }
.scenario[data-outcome="rejected"]::after { background: var(--red); }
.scenario[hidden] { display: none; }
.scenario-top { display: flex; justify-content: space-between; gap: 1rem; }
.status { font-size: .76rem; font-weight: 900; letter-spacing: .06em; text-transform: uppercase; }
.status.closed { color: var(--teal-dark); }
.status.blocked { color: var(--amber); }
.status.rejected { color: var(--red); }
.scenario dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem .75rem; margin: 1rem 0; }
.scenario dt { color: var(--muted); }
.scenario dd { margin: 0; font-weight: 720; }
details { border: 1px solid var(--line); border-radius: 1rem; background: var(--surface); }
summary { padding: 1.15rem; cursor: pointer; font-weight: 800; }
.table-wrap { overflow-x: auto; padding: 0 1rem 1rem; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
caption { padding: .4rem 0 1rem; text-align: left; color: var(--muted); }
th, td { padding: .75rem; border-top: 1px solid var(--line); text-align: left; vertical-align: top; }
th { font-size: .74rem; letter-spacing: .07em; text-transform: uppercase; }
.nonclaim-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.nonclaim { padding: 1rem; box-shadow: none; }
.nonclaim b { display: block; color: var(--red); }
.footer { padding: 2rem 0 4rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .9rem; }
.footer strong { color: var(--ink); }
@media (max-width: 760px) {
  .pipeline, .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .scope-grid, .scenario-grid, .nonclaim-grid { grid-template-columns: 1fr; }
}
@media (max-width: 480px) {
  .shell { width: min(100% - 1.15rem, 1120px); }
  .hero { padding-top: 2.4rem; }
  .hero-meta, .pipeline, .metric-grid { grid-template-columns: 1fr; }
  .pipeline li { min-height: auto; }
  .scenario-top { display: block; }
  .scenario dl { grid-template-columns: 1fr; }
  .scenario dd { margin-bottom: .45rem; }
  th, td { padding: .65rem .45rem; }
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1714;
    --surface: #13221d;
    --surface-2: #1a3028;
    --ink: #ecf6f1;
    --muted: #a8beb5;
    --line: #2b483e;
    --teal: #63d9c1;
    --teal-dark: #88ead6;
    --lime: #b9e765;
    --amber: #ffc15e;
    --red: #ff8d85;
    --shadow: 0 18px 48px rgba(0, 0, 0, .25);
  }
  .callout { background: #382800; color: #ffe7ac; }
  .badge { color: #173008; }
}
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
""".strip()

SCRIPT = r"""
(() => {
  const buttons = Array.from(document.querySelectorAll('[data-filter]'));
  const cards = Array.from(document.querySelectorAll('[data-outcome]'));
  for (const button of buttons) {
    button.addEventListener('click', () => {
      const selected = button.dataset.filter;
      for (const item of buttons) item.setAttribute('aria-pressed', String(item === button));
      for (const card of cards) card.hidden = selected !== 'all' && card.dataset.outcome !== selected;
    });
  }
})();
""".strip()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceRejected("visual presentation: " + message)


def _document(directory: Path, name: str):
    return _read_json(directory / _path(name))


def _link(directory: Path, name: str) -> dict:
    name = _path(name)
    raw = _read_bytes(directory / name)
    return {
        "path": name,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _all_false(value: object) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and all(item is False for item in value.values())
    )


def _resolution(value: object, status: str, state: str) -> None:
    _require(isinstance(value, dict), "invalid resolution document")
    findings = value.get("finding_resolutions")
    _require(
        isinstance(findings, list)
        and len(findings) == 1
        and findings[0].get("status") == status
        and findings[0].get("blocking") is True
        and value.get("state") == state,
        "unexpected finding resolution",
    )


def _validate_source(source: object) -> dict:
    _require(
        isinstance(source, dict)
        and source.get("schema_version") == "vulnevidenceops.demo-source-provenance.v1"
        and _hex(source.get("commit_sha"), 40)
        and _hex(source.get("tree_sha"), 40)
        and type(source.get("worktree_clean")) is bool
        and source.get("source_authentication_established") is False,
        "invalid source provenance",
    )
    return source


def derive_presentation(directory: Path, *, source: dict | None = None) -> dict:
    """Derive the complete presentation model from real bounded evidence files."""
    source = _validate_source(
        _document(directory, "source-provenance.json") if source is None else source
    )
    summary = _document(directory, "summary.json")
    environment = _document(directory, "execution-environment.json")
    packet = _document(directory, "doraops/input.json")
    datagov_receipt = _document(directory, "datagovops/consumer/receipt.json")
    datagov_signature = _document(
        directory, "datagovops/consumer/signature-verification.json"
    )
    datagov_policy = _document(directory, "datagovops/consumer/key-policy.json")
    dora_receipt = _document(directory, "doraops/consumer/receipt.json")
    dora_signature = _document(directory, "doraops/consumer/signature-verification.json")
    risk = _document(directory, "doraops/consumer/risk-decision.json")
    before = _document(directory, "doraops/consumer/resolution-before.json")
    remediation = _document(directory, "doraops/consumer/resolution-remediation.json")
    final = _document(directory, "doraops/consumer/resolution-final.json")
    missing = _document(directory, "attention/missing-retest/consumer/receipt.json")
    failed = _document(directory, "attention/failed-retest/consumer/receipt.json")

    _require(
        isinstance(summary, dict)
        and summary.get("scope") == "local-synthetic-demo"
        and summary.get("positive_case_accepted") is True
        and summary.get("upstream_datagovops_accepted") is True
        and summary.get("upstream_signature_verified") is True
        and summary.get("doraops_signature_verified") is True
        and summary.get("finding_phases")
        == {"before": "open", "remediation": "remediation_submitted", "final": "closed"}
        and summary.get("risk_residual_level") == "high"
        and summary.get("risk_control_credit") == 0
        and summary.get("requires_human_review") is True
        and summary.get("incident_created") is False
        and summary.get("production_interoperability_established") is False,
        "summary does not prove the declared positive outcome",
    )
    _require(
        datagov_receipt.get("accepted") is True
        and datagov_receipt.get("requires_human_review") is True
        and _all_false(datagov_receipt.get("non_claims"))
        and datagov_signature.get("signature_valid") is True
        and datagov_signature.get("packet_binding_valid") is True
        and datagov_signature.get("consumer_key_policy_satisfied") is True
        and datagov_signature.get("key_current_at_signing_and_verification") is True
        and datagov_signature.get("public_test_key") is True
        and _all_false(datagov_signature.get("non_claims"))
        and datagov_policy.get("audience")
        == "datagovops.local-synthetic-evidence-consumer"
        and datagov_policy.get("purpose") == "register-dossier-evidence",
        "DataGovOps signature scope or receipt differs",
    )
    _require(
        dora_receipt.get("accepted") is True
        and dora_receipt.get("doraops_handoff_signature_verified") is True
        and dora_receipt.get("finding_status") == "closed"
        and dora_receipt.get("resolution_state") == "successful_with_findings"
        and dora_receipt.get("risk_residual_level") == "high"
        and dora_receipt.get("risk_control_credit") == 0
        and dora_receipt.get("risk_remediation_required") is True
        and dora_receipt.get("requires_human_review") is True
        and _all_false(dora_receipt.get("non_claims"))
        and dora_signature.get("signature_valid") is True
        and dora_signature.get("packet_binding_valid") is True
        and dora_signature.get("consumer_key_policy_satisfied") is True
        and dora_signature.get("key_current_at_signing_and_verification") is True
        and dora_signature.get("public_test_key") is True
        and dora_signature.get("audience")
        == "doraops.local-synthetic-risk-remediation-consumer"
        and dora_signature.get("purpose") == "consume-risk-remediation-evidence"
        and set(dora_signature.get("members_sha256", {}))
        == {"handoff", "source_packet", "datagovops_receipt", "change_completion"}
        and _all_false(dora_signature.get("non_claims")),
        "DORAOps signature scope, binding, or receipt differs",
    )
    _require(
        risk.get("inherent_score") == 9
        and risk.get("residual_score") == 9
        and risk.get("inherent_level") == "high"
        and risk.get("residual_level") == "high"
        and risk.get("control_credit") == 0
        and risk.get("control_digests") == []
        and risk.get("remediation_required") is True
        and risk.get("risk_acceptance_required") is False
        and risk.get("treatment", {}).get("treatment") == "mitigate",
        "native DORAOps risk decision differs",
    )
    _resolution(before, "open", "blocked")
    _resolution(remediation, "remediation_submitted", "blocked")
    _resolution(final, "closed", "successful_with_findings")
    _require(
        missing.get("accepted") is True
        and missing.get("finding_status") == "remediation_submitted"
        and missing.get("resolution_state") == "blocked"
        and missing.get("risk_residual_level") == "high"
        and missing.get("risk_control_credit") == 0
        and failed.get("accepted") is True
        and failed.get("finding_status") == "retest_failed"
        and failed.get("resolution_state") == "blocked"
        and failed.get("risk_residual_level") == "high"
        and failed.get("risk_control_credit") == 0,
        "attention scenarios do not remain blocked",
    )
    _require(
        packet.get("handoff", {}).get("synthetic") is True
        and packet["handoff"].get("requires_human_review") is True
        and packet["handoff"].get("incident_created") is False,
        "input boundary overstates the synthetic demo",
    )
    _require(
        isinstance(environment, dict)
        and environment.get("installation_mode")
        in {"prepared-environment", "isolated-wheels"}
        and type(environment.get("exact_runtime_wheel_bytes_verified")) is bool
        and environment.get("dependency_wheel_reproducibility_established") is False
        and isinstance(environment.get("dependency_versions"), dict)
        and all(
            isinstance(name, str) and isinstance(version, str)
            for name, version in environment["dependency_versions"].items()
        ),
        "execution environment claims differ",
    )

    negatives = summary.get("negative_cases")
    _require(
        isinstance(negatives, dict) and set(negatives) == set(NEGATIVE_EXPECTATIONS),
        "negative scenario inventory differs",
    )
    negative_cases = []
    for name in sorted(NEGATIVE_EXPECTATIONS):
        expected = NEGATIVE_EXPECTATIONS[name]
        rejection_path = f"negative/{name}/rejection.json"
        rejection = _document(directory, rejection_path)
        _require(
            isinstance(rejection, dict)
            and rejection.get("accepted") is False
            and rejection.get("exit_code") == 2
            and rejection.get("error_code") == expected
            and negatives[name] == rejection,
            f"negative scenario {name} differs",
        )
        negative_cases.append(
            {
                "id": name,
                "accepted": False,
                "error_code": expected,
                "evidence": _link(directory, rejection_path),
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "local-synthetic-demo",
        "title": TITLE,
        "narrative": NARRATIVE,
        "duration_minutes": 5,
        "source": {
            "commit_sha": source["commit_sha"],
            "tree_sha": source["tree_sha"],
            "worktree_clean": source["worktree_clean"],
            "source_authentication_established": False,
        },
        "environment": {
            "python": environment.get("python"),
            "installation_mode": environment["installation_mode"],
            "exact_runtime_wheel_bytes_verified": environment[
                "exact_runtime_wheel_bytes_verified"
            ],
            "dependency_versions": dict(sorted(environment["dependency_versions"].items())),
            "evidence": _link(directory, "execution-environment.json"),
        },
        "signature_scopes": [
            {
                "system": "DataGovOps",
                "verified": True,
                "public_test_key": True,
                "audience": datagov_policy["audience"],
                "purpose": datagov_policy["purpose"],
                "receipt": _link(directory, "datagovops/consumer/receipt.json"),
                "verification": _link(
                    directory, "datagovops/consumer/signature-verification.json"
                ),
            },
            {
                "system": "DORAOps",
                "verified": True,
                "public_test_key": True,
                "audience": dora_signature["audience"],
                "purpose": dora_signature["purpose"],
                "receipt": _link(directory, "doraops/consumer/receipt.json"),
                "verification": _link(
                    directory, "doraops/consumer/signature-verification.json"
                ),
            },
        ],
        "risk": {
            "inherent_score": risk["inherent_score"],
            "inherent_level": risk["inherent_level"],
            "residual_score": risk["residual_score"],
            "residual_level": risk["residual_level"],
            "control_credit": risk["control_credit"],
            "remediation_required": risk["remediation_required"],
            "risk_acceptance_required": risk["risk_acceptance_required"],
            "decision": _link(directory, "doraops/consumer/risk-decision.json"),
        },
        "scenarios": [
            {
                "id": "passing-retest",
                "outcome": "closed",
                "accepted": True,
                "finding_status": dora_receipt["finding_status"],
                "resolution_state": dora_receipt["resolution_state"],
                "risk_level": dora_receipt["risk_residual_level"],
                "control_credit": dora_receipt["risk_control_credit"],
                "evidence": [
                    _link(directory, "doraops/consumer/receipt.json"),
                    _link(directory, "doraops/consumer/resolution-final.json"),
                ],
            },
            {
                "id": "missing-retest",
                "outcome": "blocked",
                "accepted": True,
                "finding_status": missing["finding_status"],
                "resolution_state": missing["resolution_state"],
                "risk_level": missing["risk_residual_level"],
                "control_credit": missing["risk_control_credit"],
                "evidence": [
                    _link(directory, "attention/missing-retest/consumer/receipt.json")
                ],
            },
            {
                "id": "failed-retest",
                "outcome": "blocked",
                "accepted": True,
                "finding_status": failed["finding_status"],
                "resolution_state": failed["resolution_state"],
                "risk_level": failed["risk_residual_level"],
                "control_credit": failed["risk_control_credit"],
                "evidence": [
                    _link(directory, "attention/failed-retest/consumer/receipt.json")
                ],
            },
            {
                "id": "tampered-completion",
                "outcome": "rejected",
                "accepted": False,
                "finding_status": None,
                "resolution_state": "rejected",
                "risk_level": None,
                "control_credit": None,
                "error_code": NEGATIVE_EXPECTATIONS["rehashed-completion"],
                "evidence": [
                    _link(directory, "negative/rehashed-completion/rejection.json")
                ],
            },
        ],
        "negative_cases": negative_cases,
        "non_claims": {
            "synthetic_fixture": packet["handoff"]["synthetic"],
            "human_review_required": summary["requires_human_review"],
            "incident_created": summary["incident_created"],
            "production_interoperability_established": summary[
                "production_interoperability_established"
            ],
            "source_authentication_established": source[
                "source_authentication_established"
            ],
            "independent_rebuild_is_bit_reproducible": environment[
                "dependency_wheel_reproducibility_established"
            ],
            "real_remediation_effectiveness_established": dora_receipt["non_claims"][
                "real_remediation_effectiveness_established"
            ],
            "risk_acceptance_approved": dora_receipt["non_claims"][
                "risk_acceptance_approved"
            ],
            "regulatory_compliance_determined": dora_receipt["non_claims"][
                "regulatory_compliance_determined"
            ],
        },
    }


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _label(identifier: str) -> str:
    return identifier.replace("-", " ").title()


def _anchor(link: dict, label: str) -> str:
    return (
        f'<a href="{_escape(link["path"])}" target="_blank" rel="noopener" '
        f'title="SHA-256 {_escape(link["sha256"])}">{_escape(label)}</a>'
    )


def _hash_source(value: str) -> str:
    return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode("ascii")


def _embedded_json(value: dict) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return (
        raw.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html(presentation: dict) -> str:
    """Render a deterministic, responsive report with no external resources."""
    source = presentation["source"]
    environment = presentation["environment"]
    risk = presentation["risk"]
    scopes = "".join(
        f"""
        <article class="scope-card">
          <div class="scope-head"><div><p class="label">Independent scope</p><h3>{_escape(scope['system'])}</h3></div><span class="badge">Verified</span></div>
          <div class="scope-value"><span>Audience</span><code>{_escape(scope['audience'])}</code></div>
          <div class="scope-value"><span>Purpose</span><code>{_escape(scope['purpose'])}</code></div>
          <div class="evidence-links">{_anchor(scope['receipt'], 'Receipt JSON')}{_anchor(scope['verification'], 'Signature JSON')}</div>
        </article>"""
        for scope in presentation["signature_scopes"]
    )
    scenario_copy = {
        "passing-retest": "Configured synthetic independent retest passes; the finding closes while residual risk stays high.",
        "missing-retest": "Completion metadata is accepted, but no retest means resolution remains blocked.",
        "failed-retest": "The failed retest is retained as evidence; the finding remains blocked.",
        "tampered-completion": "Rehashed completion data with the old signature is rejected before any receipt is accepted.",
    }
    scenarios = "".join(
        f"""
        <article class="scenario" data-outcome="{_escape(item['outcome'])}" aria-labelledby="scenario-{_escape(item['id'])}">
          <div class="scenario-top"><h3 id="scenario-{_escape(item['id'])}">{_escape(_label(item['id']))}</h3><span class="status {_escape(item['outcome'])}">{_escape(item['outcome'])}</span></div>
          <p>{_escape(scenario_copy[item['id']])}</p>
          <dl>
            <dt>Accepted</dt><dd>{_escape(str(item['accepted']).lower())}</dd>
            <dt>Finding</dt><dd>{_escape(item['finding_status'] if item['finding_status'] is not None else 'not created')}</dd>
            <dt>Resolution</dt><dd>{_escape(item['resolution_state'])}</dd>
            <dt>Risk</dt><dd>{_escape(item['risk_level'] if item['risk_level'] is not None else 'not assessed')}</dd>
          </dl>
          <div class="evidence-links">{''.join(_anchor(link, f'Evidence {index}') for index, link in enumerate(item['evidence'], 1))}</div>
        </article>"""
        for item in presentation["scenarios"]
    )
    negative_rows = "".join(
        f"<tr><td>{_escape(_label(item['id']))}</td><td><code>{_escape(item['error_code'])}</code></td><td>{_anchor(item['evidence'], 'Rejection JSON')}</td></tr>"
        for item in presentation["negative_cases"]
    )
    nonclaim_labels = {
        "synthetic_fixture": "Synthetic fixture",
        "human_review_required": "Human review required",
        "incident_created": "Incident created",
        "production_interoperability_established": "Production interoperability established",
        "source_authentication_established": "Source authentication established",
        "independent_rebuild_is_bit_reproducible": "Independent rebuild is bit-reproducible",
        "real_remediation_effectiveness_established": "Real remediation effectiveness established",
        "risk_acceptance_approved": "Risk acceptance approved",
        "regulatory_compliance_determined": "Regulatory compliance determined",
    }
    nonclaims = "".join(
        f'<div class="nonclaim"><span class="label">Boundary</span><b>{_escape(str(value).lower())}</b>{_escape(nonclaim_labels[name])}</div>'
        for name, value in presentation["non_claims"].items()
    )
    csp = (
        "default-src 'none'; "
        f"style-src 'sha256-{_hash_source(STYLE)}'; "
        f"script-src 'sha256-{_hash_source(SCRIPT)}'; "
        "img-src 'self' data:; connect-src 'none'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta http-equiv="Content-Security-Policy" content="{_escape(csp)}">
  <title>{_escape(presentation['title'])} · VulnEvidenceOps</title>
  <style>{STYLE}</style>
</head>
<body>
  <a class="skip-link" href="#main">Skip to evidence</a>
  <header class="hero">
    <div class="shell">
      <p class="eyebrow">Evidence-linked · synthetic · {_escape(presentation['duration_minutes'])} minutes</p>
      <h1>{_escape(presentation['title'])}</h1>
      <p class="lede">{_escape(presentation['narrative'])} turns one synthetic finding into a dossier, two independently scoped signature decisions, and a native risk/remediation outcome. Every result below links to the JSON that produced it.</p>
      <div class="hero-meta">
        <div class="meta-card"><span class="label">Exact source commit</span><br><code>{_escape(source['commit_sha'])}</code></div>
        <div class="meta-card"><span class="label">Execution</span><br><strong>{_escape(environment['installation_mode'])}</strong> · Python {_escape(environment['python'])}</div>
      </div>
    </div>
  </header>
  <main id="main">
    <section class="section"><div class="shell">
      <p class="label">01 · Provenance chain</p><h2>Four bounded stages, no invented handoff</h2>
      <p class="section-copy">The source producer, DataGovOps consumer, DORAOps signer, and DORAOps native APIs each preserve a distinct responsibility.</p>
      <ol class="pipeline">
        <li><strong>VulnEvidenceOps</strong><span>Builds the synthetic finding dossier and evidence catalog.</span></li>
        <li><strong>DataGovOps</strong><span>Reconsumes and registers evidence under its own policy.</span></li>
        <li><strong>DORAOps signature</strong><span>Binds handoff, source, upstream receipt, and completion.</span></li>
        <li><strong>DORAOps decision</strong><span>Computes risk and finding resolution through native APIs.</span></li>
      </ol>
    </div></section>
    <section class="section"><div class="shell">
      <p class="label">02 · Independent trust scopes</p><h2>Two signatures, two audiences</h2>
      <p class="section-copy">Both checks use public RFC test keys. They demonstrate binding and replay rejection, not production identity or key custody.</p>
      <div class="scope-grid">{scopes}</div>
    </div></section>
    <section class="section"><div class="shell">
      <p class="label">03 · Consumer-owned judgment</p><h2>Closure and risk are separate decisions</h2>
      <div class="callout"><strong>Finding closure does not automatically reduce risk.</strong>The passing synthetic retest closes the finding. DORAOps still records residual risk as high, score 9, with zero control credit and remediation required.</div>
      <div class="metric-grid">
        <div class="metric"><span class="label">Inherent</span><span class="metric-value">{_escape(risk['inherent_score'])}</span><small>{_escape(risk['inherent_level'])}</small></div>
        <div class="metric"><span class="label">Residual</span><span class="metric-value">{_escape(risk['residual_score'])}</span><small>{_escape(risk['residual_level'])}</small></div>
        <div class="metric"><span class="label">Control credit</span><span class="metric-value">{_escape(risk['control_credit'])}</span><small>no automatic credit</small></div>
        <div class="metric"><span class="label">Remediation</span><span class="metric-value">Required</span><small>{_anchor(risk['decision'], 'Risk decision JSON')}</small></div>
      </div>
    </div></section>
    <section class="section"><div class="shell">
      <p class="label">04 · Outcome comparison</p><h2>Pass, block, or reject</h2>
      <p class="section-copy">Use the filters to compare the actual consumer outcomes. Acceptance of metadata is not proof of remediation.</p>
      <div class="filters" aria-label="Filter outcome cards">
        <button type="button" data-filter="all" aria-pressed="true">All outcomes</button>
        <button type="button" data-filter="closed" aria-pressed="false">Closed</button>
        <button type="button" data-filter="blocked" aria-pressed="false">Blocked</button>
        <button type="button" data-filter="rejected" aria-pressed="false">Rejected</button>
      </div>
      <div class="scenario-grid" aria-live="polite">{scenarios}</div>
    </div></section>
    <section class="section"><div class="shell">
      <p class="label">05 · Fail-closed evidence</p><h2>Fourteen required rejection boundaries</h2>
      <details><summary>Inspect the complete negative-case inventory</summary><div class="table-wrap">
        <table><caption>Every case exits 2 and produces no accepted consumer receipt.</caption><thead><tr><th>Scenario</th><th>Error code</th><th>Evidence</th></tr></thead><tbody>{negative_rows}</tbody></table>
      </div></details>
    </div></section>
    <section class="section"><div class="shell">
      <p class="label">Scope · What this does not prove</p><h2>Public synthetic reference, not production assurance</h2>
      <div class="nonclaim-grid">{nonclaims}</div>
    </div></section>
  </main>
  <footer class="footer"><div class="shell"><strong>VulnEvidenceOps portfolio demo.</strong> Source tree <code>{_escape(source['tree_sha'])}</code>. All identities, dates, judgments, data, and signing keys are synthetic. Human review remains required.</div></footer>
  <script id="presentation-data" type="application/json">{_embedded_json(presentation)}</script>
  <script>{SCRIPT}</script>
</body>
</html>
"""


def create_presentation(directory: Path, *, source: dict) -> dict:
    """Write new presentation files without overwriting retained evidence."""
    paths = (directory / "presentation.json", directory / "index.html")
    if any(path.exists() for path in paths):
        raise EvidenceRejected("visual presentation output already exists")
    presentation = derive_presentation(directory, source=source)
    raw = _json_bytes(presentation)
    rendered = render_html(presentation).encode("utf-8")
    _require(len(raw) <= MAX_FILE_BYTES and len(rendered) <= MAX_FILE_BYTES, "files oversized")
    with paths[0].open("xb") as output:
        output.write(raw)
    with paths[1].open("xb") as output:
        output.write(rendered)
    verify_presentation(directory, source=source)
    return presentation


def verify_presentation(directory: Path, *, source: dict | None = None) -> dict:
    """Re-derive and byte-compare the machine model and self-contained HTML."""
    expected = derive_presentation(directory, source=source)
    actual = _document(directory, "presentation.json")
    _require(actual == expected, "machine model differs from underlying evidence")
    rendered = render_html(expected).encode("utf-8")
    _require(_read_bytes(directory / "index.html") == rendered, "HTML differs from evidence")
    _require(
        not re.search(rb"https?://|//[A-Za-z0-9]|fetch\s*\(|XMLHttpRequest|WebSocket", rendered),
        "external resource or network API detected",
    )
    return {
        "verified": True,
        "schema_version": SCHEMA_VERSION,
        "source_commit_sha": expected["source"]["commit_sha"],
        "negative_case_count": len(expected["negative_cases"]),
        "scenario_count": len(expected["scenarios"]),
        "html_sha256": hashlib.sha256(rendered).hexdigest(),
    }
