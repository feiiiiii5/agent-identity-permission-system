from pydantic import BaseModel, Field, validator
from typing import Optional, List
from enum import Enum


class TokenIssueRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID")
    client_secret: str = Field(..., min_length=1, max_length=256, description="Client secret")
    capabilities: List[str] = Field(default_factory=list, max_items=50, description="Requested capabilities")
    delegated_user: Optional[str] = Field(None, max_length=128, description="Delegated user ID")
    max_uses: Optional[int] = Field(None, ge=0, le=10000, description="Max token uses")
    task_id: Optional[str] = Field(None, max_length=128, description="Task ID")
    trace_id: Optional[str] = Field(None, max_length=32, description="Trace ID for audit")
    task_description: Optional[str] = Field(None, max_length=500, description="Task description")
    nonce: Optional[str] = Field(None, max_length=128, description="Nonce for replay protection")

    @validator("agent_id")
    def validate_agent_id(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("agent_id cannot be empty")
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("agent_id contains invalid characters")
        return v

    @validator("capabilities")
    def validate_capabilities(cls, v):
        seen = set()
        for cap in v:
            cap = cap.strip()
            if not cap:
                continue
            if len(cap) > 128:
                raise ValueError(f"Capability too long: {cap[:20]}...")
            if cap in seen:
                raise ValueError(f"Duplicate capability: {cap}")
            seen.add(cap)
        return list(seen)


class TokenDelegateRequest(BaseModel):
    parent_token: str = Field(..., min_length=1, max_length=8192, description="Parent token")
    target_agent_id: str = Field(..., min_length=1, max_length=128, description="Target agent ID")
    requested_capabilities: List[str] = Field(default_factory=list, max_items=50, description="Requested capabilities")
    delegated_user: Optional[str] = Field(None, max_length=128, description="Delegated user")
    one_time: bool = Field(False, description="One-time use token")
    task_id: Optional[str] = Field(None, max_length=128, description="Task ID")

    @validator("target_agent_id")
    def validate_target_agent_id(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("target_agent_id cannot be empty")
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("target_agent_id contains invalid characters")
        return v


class TokenVerifyRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=8192, description="Token to verify")
    verifier_agent_id: str = Field(default="agent_data_001", max_length=128, description="Verifier agent ID")
    verifier_secret: str = Field(default="", max_length=256, description="Verifier secret")
    required_capability: Optional[str] = Field(None, max_length=128, description="Required capability")
    dpop_proof: Optional[str] = Field(None, max_length=4096, description="DPoP proof")


class TokenRevokeRequest(BaseModel):
    jti: Optional[str] = Field(None, max_length=128, description="Token JTI")
    token: Optional[str] = Field(None, max_length=8192, description="Token string")
    cascade: bool = Field(default=True, description="Cascade revoke child tokens")


class TokenRefreshRequest(BaseModel):
    jti: str = Field(..., min_length=1, max_length=128, description="Token JTI")
    ttl_seconds: int = Field(default=3600, ge=60, le=86400, description="New TTL in seconds")


class InjectionScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="Text to scan")

    @validator("text")
    def validate_text(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("text cannot be empty")
        return v


class RiskDecisionRequest(BaseModel):
    risk_score: float = Field(..., ge=0, le=100, description="Risk score")
    trace_id: Optional[str] = Field(None, max_length=32, description="Trace ID")


class PolicyEvaluateRequest(BaseModel):
    subject_id: str = Field(..., min_length=1, max_length=128, description="Subject ID")
    action: str = Field(..., min_length=1, max_length=128, description="Action")
    resource: str = Field(..., min_length=1, max_length=128, description="Resource")
    context: Optional[dict] = Field(None, description="Additional context")


class ApprovalResolveRequest(BaseModel):
    approved: bool = Field(..., description="Whether approved")


class NonceRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID")


class NonceConsumeRequest(BaseModel):
    nonce: str = Field(..., min_length=1, max_length=128, description="Nonce value")
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID")


class IntentRouteRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000, description="User input text")

    @validator("text")
    def validate_text(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("text cannot be empty")
        return v


class FeishuTestMessageRequest(BaseModel):
    chat_id: Optional[str] = Field(None, max_length=128, description="Chat ID")
    user_id: Optional[str] = Field(None, max_length=128, description="User ID")
    text: str = Field(default="Hello from AgentPass!", max_length=2000, description="Message text")


class FeishuBotCommandRequest(BaseModel):
    command: str = Field(default="help", max_length=500, description="Bot command")
    user_id: Optional[str] = Field(None, max_length=128, description="User ID")
    chat_id: Optional[str] = Field(None, max_length=128, description="Chat ID")


class FeishuStartPollingRequest(BaseModel):
    chat_ids: List[str] = Field(default_factory=list, max_items=50, description="Chat IDs to poll")
    interval: float = Field(default=3.0, ge=1.0, le=30.0, description="Poll interval in seconds")


class ExportReportRequest(BaseModel):
    format: str = Field(default="html", description="Report format")
    include_audit: bool = Field(default=True, description="Include audit logs")
    include_risk: bool = Field(default=True, description="Include risk assessment")


class TokenExchangeRequest(BaseModel):
    grant_type: str = Field(default="urn:ietf:params:oauth:grant-type:token-exchange", max_length=128, description="OAuth2 grant type")
    subject_token: str = Field(..., min_length=1, max_length=8192, description="Subject token to exchange")
    subject_token_type: str = Field(default="urn:ietf:params:oauth:token-type:access_token", max_length=128, description="Subject token type")
    scope: List[str] = Field(..., min_items=1, max_items=50, description="Requested scopes")
    ttl_minutes: int = Field(default=15, ge=1, le=60, description="Requested TTL in minutes")

    @validator("grant_type")
    def validate_grant_type(cls, v):
        if v != "urn:ietf:params:oauth:grant-type:token-exchange":
            raise ValueError("Only urn:ietf:params:oauth:grant-type:token-exchange is supported")
        return v

    @validator("scope")
    def validate_scope(cls, v):
        validated = []
        for s in v:
            s = s.strip()
            if not s:
                continue
            if ":" not in s:
                raise ValueError(f"Invalid scope format (must contain ':'): {s}")
            validated.append(s)
        if not validated:
            raise ValueError("At least one scope is required")
        return validated


class TokenIntrospectRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=8192, description="Token to introspect")


class LifecycleEventRequest(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=64, description="Event type")
    user_id: str = Field(..., min_length=1, max_length=128, description="User ID")
    payload: Optional[dict] = Field(None, description="Additional event payload")

    @validator("event_type")
    def validate_event_type(cls, v):
        valid_types = ["user.suspended", "user.reactivated", "user.departed", "user.role_changed"]
        if v not in valid_types:
            raise ValueError(f"event_type must be one of {valid_types}")
        return v


class ConsentGrantRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID")
    user_id: str = Field(..., min_length=1, max_length=128, description="User ID granting consent")
    capabilities: List[str] = Field(..., min_items=1, max_items=50, description="Capabilities being consented")
    ttl_seconds: int = Field(default=86400, ge=60, le=2592000, description="Consent TTL in seconds")


class ConsentRevokeRequest(BaseModel):
    consent_id: int = Field(..., ge=1, description="Consent ID to revoke")
    revoked_by: str = Field(default="", max_length=128, description="Who revoked the consent")


class DriftDetectRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID to check for drift")


class DriftBaselineRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID to set baseline for")
    attested_by: str = Field(default="system", max_length=128, description="Who attested the baseline")


class AccessReviewCreateRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128, description="Agent ID to review")
    reviewer_id: str = Field(..., min_length=1, max_length=128, description="Reviewer user ID")
    review_type: str = Field(default="periodic", max_length=32, description="Review type")
    due_days: int = Field(default=7, ge=1, le=90, description="Days until review is due")


class AccessReviewResolveRequest(BaseModel):
    decision: str = Field(..., description="Review decision: approve, revoke, or modify")
    comment: str = Field(default="", max_length=1000, description="Review comment")

    @validator("decision")
    def validate_decision(cls, v):
        if v not in ("approve", "revoke", "modify"):
            raise ValueError("decision must be approve, revoke, or modify")
        return v
