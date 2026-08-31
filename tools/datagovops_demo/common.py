"""Independent, offline contract validation shared by the demo processes."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "examples/datagovops-demo/demo-contract.json"
MAX_JSON_BYTES = 2_000_000


class DemoRejected(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DemoRejected("invalid_json", "duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise DemoRejected("invalid_json", "non-finite JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        _invalid_constant(value)
    return number


def read_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise DemoRejected("invalid_json", "JSON input must be a bounded regular file")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DemoRejected("invalid_json", "input is not strict UTF-8 JSON") from exc


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(canonical_bytes(value) + b"\n")


def timestamp(value: str) -> int:
    try:
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
        ):
            raise ValueError("UTC required")
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.microsecond or parsed.timestamp() < 0:
            raise ValueError("non-negative whole seconds required")
        return int(parsed.timestamp())
    except (ValueError, OverflowError) as exc:
        raise DemoRejected(
            "invalid_timestamp", "demo requires UTC whole-second timestamps"
        ) from exc


FORMATS = FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def _date_time(value):
    timestamp(value)
    return True


def load_contract() -> dict:
    contract = read_json(CONTRACT_PATH)
    if contract.get("schema_version") != "vulnevidenceops.datagovops-demo-contract.v1":
        raise DemoRejected("contract_mismatch", "unknown demo contract")
    return contract


def check_runtime(spec: dict, *, installed_wheel: bool = False) -> dict:
    module = importlib.import_module(spec["package"])
    directory = Path(module.__file__).resolve().parent
    if installed_wheel and not directory.is_relative_to(Path(sys.prefix).resolve()):
        raise DemoRejected(
            "runtime_mismatch", "expected a wheel installed in the isolated environment"
        )
    if (
        module.__version__ != spec["version"]
        or importlib.metadata.version(spec["distribution"]) != spec["version"]
    ):
        raise DemoRejected("runtime_mismatch", "runtime version differs from the pinned demo")
    files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.glob("*.py"))
    }
    if files != spec["python_files_sha256"]:
        raise DemoRejected(
            "runtime_mismatch", "installed Python files differ from the pinned source"
        )
    return {
        "package": spec["package"],
        "version": module.__version__,
        "python_files_sha256": digest(files),
        "file_count": len(files),
    }


class Schemas:
    def __init__(self, contract: dict):
        self.documents = {}
        registry = Registry()  # No remote schema retrieval; all references are pinned locally.
        entries = []
        for path in sorted((ROOT / "schemas").glob("*.schema.json")):
            entries.append(
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
            schema = read_json(path)
            Draft202012Validator.check_schema(schema)
            self.documents["producer/" + path.name] = schema
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        if digest(entries) != contract["producer"]["schema_set_sha256"]:
            raise DemoRejected(
                "contract_mismatch", "producer schema set differs from the frozen v1"
            )
        for name, entry in contract["consumer"]["schemas"].items():
            path = ROOT / entry["path"]
            content = path.read_bytes()
            blob = hashlib.sha1(
                f"blob {len(content)}\0".encode("ascii") + content, usedforsecurity=False
            ).hexdigest()
            if hashlib.sha256(content).hexdigest() != entry["sha256"] or blob != entry["blob"]:
                raise DemoRejected("contract_mismatch", "consumer schema snapshot changed")
            schema = read_json(path)
            Draft202012Validator.check_schema(schema)
            self.documents["consumer/" + name + ".schema.json"] = schema
        self.registry = registry

    def validate(self, side: str, name: str, value: object) -> None:
        validator = Draft202012Validator(
            self.documents[f"{side}/{name}.schema.json"],
            registry=self.registry,
            format_checker=FORMATS,
        )
        if next(validator.iter_errors(value), None) is not None:
            raise DemoRejected("schema_incompatible", f"{side} {name} schema rejected the document")
