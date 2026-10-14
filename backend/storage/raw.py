"""Content-addressed storage for exact uploaded file bytes."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from backend.models import DatasetKind


class LocalRawTelemetryStore:
    def __init__(self, root_path: str | Path) -> None:
        self.root_path = Path(root_path)
        self.root_path.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        payload: bytes,
        *,
        dataset_kind: DatasetKind,
        dataset_id: str,
        source: str,
        source_event_id: str | None,
    ) -> str:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if dataset_kind not in ("synthetic", "official") or not dataset_id or not source:
            raise ValueError("valid dataset partition and source are required")
        metadata = json.dumps(
            {"dataset_kind": dataset_kind, "dataset_id": dataset_id,
             "source": source, "source_event_id": source_event_id},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(metadata + b"\0" + payload).hexdigest()
        target_dir = self.root_path / digest[:2]
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / digest
        self._write_once(target, payload)
        self._write_once(target_dir / f"{digest}.json", metadata)
        return digest

    @staticmethod
    def _write_once(target: Path, content: bytes) -> None:
        if target.exists():
            if target.read_bytes() != content:
                raise ValueError("raw reference collision or altered stored bytes")
            return
        fd, temporary = tempfile.mkstemp(prefix=".raw-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.read_bytes() != content:
                    raise ValueError("raw reference collision or altered stored bytes")
        finally:
            os.unlink(temporary)

    def get(self, raw_ref: str) -> bytes:
        if not re.fullmatch(r"[a-f0-9]{64}", raw_ref):
            raise ValueError("invalid raw reference")
        return (self.root_path / raw_ref[:2] / raw_ref).read_bytes()

    def get_metadata(self, raw_ref: str) -> dict:
        """Return file-level provenance, including files whose records all failed."""
        if not re.fullmatch(r"[a-f0-9]{64}", raw_ref):
            raise ValueError("invalid raw reference")
        return json.loads((self.root_path / raw_ref[:2] / f"{raw_ref}.json").read_bytes())
