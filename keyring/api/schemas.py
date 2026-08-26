from __future__ import annotations

from pydantic import BaseModel


class SessionOpenBody(BaseModel):
    provider: str | None = None


class RevokeBody(BaseModel):
    reason: str | None = None


class DestroyBody(BaseModel):
    typedConfirmation: str
    approvalId: str


class ErasureBody(BaseModel):
    typedConfirmation: str
    approvalId: str


class ApprovalCreateBody(BaseModel):
    operation: str
    targetId: str
    recordCount: int = 0


class EncryptBody(BaseModel):
    subjectId: str
    table: str
    column: str
    recordId: str
    plaintext: str


class DecryptBody(BaseModel):
    envelopeId: str


class SettingsPatchBody(BaseModel):
    rotationIntervalDays: int | None = None
    alertThreshold: int | None = None
