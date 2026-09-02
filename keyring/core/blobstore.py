"""Filesystem store for streamed file ciphertext (FR-2.5 extended to real
files). The database keeps envelope metadata — wrapped DEK, nonces,
algorithm, AAD inputs — exactly as for every other envelope; only the framed
ciphertext bytes for file uploads live here, addressed by `Envelope.blob_ref`
(a UUID string, always the same value as the owning `FileObject.id`).

This is a deliberate trade-off, not a drop-in replacement for storing
ciphertext in the database: a restored `keyring.db` and a stale blob
directory can drift apart, so a missing blob is indistinguishable from a
successfully crypto-shredded one at this layer. Callers must treat a missing
blob as `DecryptFailed` (never a distinct error) and separately surface
`blobPresent` in read-only inspection endpoints so that distinction is never
silently lost. See THREAT_MODEL.md.
"""
from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from keyring.config import settings

# Refs are always UUID4 strings (the FileObject id). Rejecting anything else
# is the traversal guard — a ref is never taken from a client-controlled path
# component, but this makes that invariant load-bearing rather than assumed.
_REF_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class InvalidBlobRef(ValueError):
    pass


def _root() -> Path:
    root = Path(settings.blob_store_path)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _resolve(ref: str) -> Path:
    if not _REF_RE.match(ref):
        raise InvalidBlobRef(f"not a valid blob ref: {ref!r}")
    return _root() / f"{ref}.enc"


@contextmanager
def write_stream(ref: str) -> Iterator[BinaryIO]:
    """Write to a temp file in the same directory, fsync, then atomically
    rename into place. On any exception the temp file (and, if a rename had
    not yet happened, only the temp file) is removed — callers never see a
    partially-written blob at the final path. This does not make the
    surrounding envelope write atomic with the blob write (the DB commit
    still happens separately) — see the module docstring."""
    final = _resolve(ref)
    tmp = final.with_suffix(final.suffix + ".tmp")
    fh = open(tmp, "wb")
    try:
        yield fh
        fh.flush()
        os.fsync(fh.fileno())
        fh.close()
        os.replace(tmp, final)
    except BaseException:
        fh.close()
        tmp.unlink(missing_ok=True)
        raise


def open_read(ref: str) -> BinaryIO:
    return open(_resolve(ref), "rb")


def exists(ref: str) -> bool:
    try:
        return _resolve(ref).is_file()
    except InvalidBlobRef:
        return False


def size(ref: str) -> int:
    return _resolve(ref).stat().st_size


def delete(ref: str) -> None:
    """Idempotent — deleting an already-missing blob is not an error, since
    cleanup paths (failed upload, retried erasure) may race harmlessly."""
    _resolve(ref).unlink(missing_ok=True)
