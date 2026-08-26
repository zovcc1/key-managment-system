"""Signed erasure certificates (section 3). Signed with HMAC-SHA256 under a
dedicated signing key — independent of any KEK/subject-key material — so a
certificate can be verified without ever touching the crypto hierarchy."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from io import BytesIO

from keyring.config import settings


class SigningKeyUnavailable(RuntimeError):
    pass


def _signing_key() -> bytes:
    raw = os.environ.get(settings.signing_key_env_var)
    if not raw:
        raise SigningKeyUnavailable(f"{settings.signing_key_env_var} is not set")
    return raw.encode("utf-8")


def build_payload(
    *, subject_id: str, subject_key_id: str, records_unreadable: int,
    tables_affected: list[str], operator: str, approval_chain: list[dict],
) -> dict:
    return {
        "subjectId": subject_id,
        "subjectKeyId": subject_key_id,
        "recordsUnreadable": records_unreadable,
        "tablesAffected": tables_affected,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operator": operator,
        "approvalChain": approval_chain,
        "boundary": (
            "Crypto-shredding covers data encrypted by this system. Plaintext "
            "exported to spreadsheets, analytics pipelines, or email before "
            "deletion is not covered."
        ),
    }


def sign_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_signing_key(), canonical, hashlib.sha256).hexdigest()


def verify_signature(payload: dict, signature: str) -> bool:
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)


def export_json(cert_row) -> bytes:
    return json.dumps(
        {
            "id": cert_row.id,
            "payload": cert_row.payload,
            "signature": cert_row.signature,
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8")


def export_pdf(cert_row, locale: str = "en") -> bytes:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas

    from keyring.i18n import t

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    y = height - 72

    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, y, t("certificate.title", locale))
    y -= 28

    c.setFont("Helvetica", 10)
    for line in [
        t("certificate.statement", locale),
        "",
        f"Certificate ID: {cert_row.id}",
        f"Subject ID: {cert_row.payload['subjectId']}",
        f"Subject Key ID: {cert_row.payload['subjectKeyId']}",
        f"Records rendered unreadable: {cert_row.payload['recordsUnreadable']}",
        f"Tables affected: {', '.join(cert_row.payload['tablesAffected'])}",
        f"Timestamp: {cert_row.payload['timestamp']}",
        f"Operator: {cert_row.payload['operator']}",
        f"Signature: {cert_row.signature}",
        "",
        t("certificate.boundary_notice", locale),
    ]:
        for wrapped in _wrap(line, 95):
            c.drawString(72, y, wrapped)
            y -= 14
        y -= 4

    c.showPage()
    c.save()
    return buf.getvalue()


def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    words = text.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
