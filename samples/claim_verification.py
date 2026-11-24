# Excerpt from blackwing/storage/claims.py
# Every claim in a finding must cite evidence; each link is rechecked by SHA-256 on every read.
# Copied without changes from the private Blackwing source. Imports and the rest of the
# module are omitted, so this file does not run on its own.
# Copyright (c) 2026 softdyne. All rights reserved. Shown for review only; see LICENSE.

"""Claim-level evidence for findings.

A finding states several material claims, for example "the endpoint returns another user's
order" and "no authorization header is required". Each claim must link to the specific saved
artifacts that support it:

* a **traffic snapshot**: the immutable copy of a captured HTTP exchange bound to the finding,
  optionally narrowed to its request or response body;
* a **proof artifact**: a saved verification report bound to the finding.

Links record the hashes they expect. Verification re-checks, for every link, that the artifact
still exists, belongs to the finding's task, and still matches both the stored hash and the
bytes on disk. Results are computed on every read, so tampering or loss shows up immediately.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from ._base import _StoreBase
from .errors import StoreValidationError

MAX_CLAIMS = 20
MAX_EVIDENCE_PER_CLAIM = 10
MAX_CLAIM_CHARS = 1000
EVIDENCE_PARTS = ("exchange", "request", "response")
PREVIEW_CHARS = 300

LINK_VERIFIED = "verified"
LINK_MISSING = "missing"
LINK_WRONG_TASK = "wrong_task"
LINK_HASH_MISMATCH = "hash_mismatch"


# ── Input validation ────────────────────────────────────────────────────────


def claim_text_key(text: str) -> str:
    """Normalize claim text for deduplication: case-insensitive, whitespace collapsed."""
    return re.sub(r"\s+", " ", str(text or "")).strip().casefold()


def _validate_evidence_ref(ref: Any, traffic_ids: set[int], has_report: bool, n: int) -> dict[str, Any]:
    if not isinstance(ref, dict):
        raise StoreValidationError(f"claim {n}: each evidence item must be an object")
    part = str(ref.get("part") or "exchange").strip().lower()
    if part not in EVIDENCE_PARTS:
        raise StoreValidationError(f"claim {n}: evidence part must be one of {list(EVIDENCE_PARTS)}")
    if ref.get("verification_report"):
        if not has_report:
            raise StoreValidationError(
                f"claim {n}: cites the verification report, but no verification_report_path was given"
            )
        return {"kind": "proof_artifact", "part": "exchange"}
    raw_tid = ref.get("traffic_id")
    try:
        tid = int(raw_tid) if raw_tid is not None else -1
    except (TypeError, ValueError):
        tid = -1
    if tid <= 0:
        raise StoreValidationError(f"claim {n}: evidence needs a traffic_id or verification_report: true")
    if tid not in traffic_ids:
        raise StoreValidationError(
            f"claim {n}: traffic_id {tid} is not among this finding's traffic_refs; cite only evidence you bind"
        )
    return {"kind": "traffic_snapshot", "traffic_id": tid, "part": part}


def validate_claims(claims: Any, *, traffic_ids: set[int], has_report: bool) -> list[dict[str, Any]]:
    """Check the ``claims`` argument of ``report_finding`` and return it normalized.

    Every claim needs text and at least one evidence item, and every evidence item must name an
    artifact bound by the same call: a ``traffic_id`` from ``traffic_refs`` or the verification report.
    """
    if not isinstance(claims, list) or not claims:
        raise StoreValidationError(
            "A finding requires claims: a list of {text, evidence: [{traffic_id, part} | {verification_report: true}]}"
        )
    if len(claims) > MAX_CLAIMS:
        raise StoreValidationError(f"at most {MAX_CLAIMS} claims per finding report")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for n, claim in enumerate(claims, start=1):
        if not isinstance(claim, dict):
            raise StoreValidationError(f"claim {n} must be an object with text and evidence")
        text = re.sub(r"\s+", " ", str(claim.get("text") or "")).strip()
        if not text:
            raise StoreValidationError(f"claim {n} has no text")
        if len(text) > MAX_CLAIM_CHARS:
            raise StoreValidationError(f"claim {n} is longer than {MAX_CLAIM_CHARS} characters")
        evidence = claim.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise StoreValidationError(f"claim {n} must link to at least one evidence artifact")
        if len(evidence) > MAX_EVIDENCE_PER_CLAIM:
            raise StoreValidationError(f"claim {n} links more than {MAX_EVIDENCE_PER_CLAIM} artifacts")
        key = claim_text_key(text)
        if key in seen:
            continue
        seen.add(key)
        refs = [_validate_evidence_ref(ref, traffic_ids, has_report, n) for ref in evidence]
        out.append({"text": text, "key": key, "evidence": refs})
    return out


# ── Hashing ─────────────────────────────────────────────────────────────────


def _file_sha256(path: Path) -> str | None:
    """SHA-256 of a file read in chunks, or None if it does not exist."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except FileNotFoundError:
        return None


def _part_hashes(part: str, req_sha: str, resp_sha: str) -> list[str]:
    if part == "request":
        return [req_sha]
    if part == "response":
        return [resp_sha]
    return [req_sha, resp_sha]


# ── Store mixin ─────────────────────────────────────────────────────────────

class ClaimsMixin(_StoreBase):
    # ... insert helpers omitted ...

    def verify_finding_claims(self, finding_id: int, task_id: int | None = None) -> dict[str, Any]:
        """Check every claim of a finding against its evidence and return claims beside their artifacts."""
        with self._read_snapshot() as conn:
            sql, params = "SELECT id, task_id FROM findings WHERE id = ?", [int(finding_id)]
            if task_id is not None:
                sql += " AND task_id = ?"
                params.append(int(task_id))
            finding = conn.execute(sql, params).fetchone()
            if finding is None:
                raise StoreValidationError(f"Finding {finding_id} not found")
            claims = conn.execute(
                "SELECT * FROM finding_claims WHERE finding_id = ? ORDER BY ordinal, id", (int(finding["id"]),)
            ).fetchall()
            views = [self._claim_view(conn, finding, claim) for claim in claims]
        if not views:
            status = "no_claims"
        elif all(v["status"] == LINK_VERIFIED for v in views):
            status = LINK_VERIFIED
        else:
            status = "failed"
        return {
            "finding_id": int(finding["id"]),
            "task_id": int(finding["task_id"]),
            "status": status,
            "claims_total": len(views),
            "claims_verified": sum(1 for v in views if v["status"] == LINK_VERIFIED),
            "claims": views,
        }

    def _claim_view(self, conn: sqlite3.Connection, finding: Any, claim: Any) -> dict[str, Any]:
        links = conn.execute(
            "SELECT * FROM finding_claim_evidence WHERE claim_id = ? ORDER BY id", (claim["id"],)
        ).fetchall()
        evidence = [self._verify_link(conn, finding, claim, link) for link in links]
        if not evidence:
            status = "unsupported"
        elif all(e["status"] == LINK_VERIFIED for e in evidence):
            status = LINK_VERIFIED
        else:
            status = "failed"
        return {
            "claim_id": int(claim["id"]),
            "ordinal": int(claim["ordinal"]),
            "text": claim["text"],
            "intent_id": int(claim["intent_id"]),
            "status": status,
            "evidence": evidence,
        }

    def _verify_link(self, conn: sqlite3.Connection, finding: Any, claim: Any, link: Any) -> dict[str, Any]:
        expected = [str(h) for h in json.loads(link["expected_hashes_json"] or "[]")]
        view: dict[str, Any] = {
            "link_id": int(link["id"]),
            "artifact_kind": link["artifact_kind"],
            "artifact_id": int(link["artifact_id"]),
            "part": link["part"],
            "expected_sha256": expected,
        }
        tasks_agree = int(link["task_id"]) == int(claim["task_id"]) == int(finding["task_id"])
        if link["artifact_kind"] == "traffic_snapshot":
            artifact, stored, owner_ok = self._snapshot_artifact(conn, finding, link)
        else:
            artifact, stored, owner_ok = self._proof_artifact(conn, finding, link)
        view.update(artifact)
        view["status"], view["reason"] = self._link_status(
            artifact_found=bool(artifact), tasks_agree=tasks_agree and owner_ok, expected=expected, stored=stored,
        )
        if view["status"] == LINK_VERIFIED:
            view["preview"] = self._evidence_preview(link["part"], stored)
        return view

    def _snapshot_artifact(
        self, conn: sqlite3.Connection, finding: Any, link: Any
    ) -> tuple[dict[str, Any], list[str], bool]:
        """Describe a cited traffic snapshot; return (description, stored hashes for the part, owned by task)."""
        snap = conn.execute(
            "SELECT s.*, b.role, b.finding_id FROM traffic_evidence_snapshots s "
            "LEFT JOIN finding_traffic_bindings b ON b.snapshot_id = s.id AND b.finding_id = ? WHERE s.id = ?",
            (finding["id"], link["artifact_id"]),
        ).fetchone()
        if snap is None:
            return {}, [], False
        description = {
            "traffic_id": int(snap["traffic_id"]),
            "method": snap["method"],
            "url": snap["url"],
            "status_code": int(snap["status"]),
            "role": snap["role"] or "",
            "byte_len": int(snap["req_len"]) + int(snap["resp_len"]) if link["part"] == "exchange"
            else int(snap["req_len"] if link["part"] == "request" else snap["resp_len"]),
        }
        bound_to_finding = snap["finding_id"] is not None
        capture = conn.execute("SELECT task_id FROM traffic_records WHERE id = ?", (snap["traffic_id"],)).fetchone()
        # The original capture may have been pruned by retention; ownership was checked when it was bound.
        capture_ok = capture is None or int(capture["task_id"]) == int(finding["task_id"])
        stored = _part_hashes(link["part"], str(snap["req_sha256"]), str(snap["resp_sha256"]))
        return description, stored, bound_to_finding and capture_ok

    @staticmethod
    def _proof_artifact(conn: sqlite3.Connection, finding: Any, link: Any) -> tuple[dict[str, Any], list[str], bool]:
        """Describe a cited proof artifact; return (description, stored hash, owned by the finding)."""
        art = conn.execute(
            "SELECT a.*, f.task_id AS owner_task FROM finding_proof_artifacts a "
            "JOIN findings f ON f.id = a.finding_id WHERE a.id = ?",
            (link["artifact_id"],),
        ).fetchone()
        if art is None:
            return {}, [], False
        description = {"kind": art["kind"], "filename": art["filename"], "byte_len": int(art["byte_len"])}
        owned = int(art["finding_id"]) == int(finding["id"]) and int(art["owner_task"]) == int(finding["task_id"])
        return description, [str(art["sha256"])], owned

    def _link_status(
        self, *, artifact_found: bool, tasks_agree: bool, expected: list[str], stored: list[str]
    ) -> tuple[str, str]:
        """Apply the checks in order: exists, same task, stored hash, bytes on disk."""
        if not artifact_found:
            return LINK_MISSING, "the cited artifact no longer exists"
        if not tasks_agree:
            return LINK_WRONG_TASK, "the cited artifact does not belong to this finding's task"
        if stored != expected:
            return LINK_HASH_MISMATCH, "the artifact's stored hash differs from the hash recorded when it was cited"
        for digest in stored:
            actual = _file_sha256(self.evidence_dir / digest[:2] / f"{digest}.bin")
            if actual is None:
                return LINK_MISSING, f"evidence blob {digest[:12]}… is missing from disk"
            if actual != digest:
                return LINK_HASH_MISMATCH, f"evidence blob {digest[:12]}… no longer matches its hash"
        return LINK_VERIFIED, ""
