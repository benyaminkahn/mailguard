"""API contract for MailGuard.

All request fields come from an untrusted email, so every field is bounded
to limit payload-size abuse. Unknown fields are rejected outright.
"""

from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# Size limits (characters). Chosen to fit real-world mail while capping abuse.
MAX_NAME_LEN = 256
MAX_ADDRESS_LEN = 320          # RFC 5321: 64 local + @ + 255 domain
MAX_SUBJECT_LEN = 998          # RFC 5322 max line length
MAX_BODY_PLAIN_LEN = 200_000
MAX_BODY_HTML_LEN = 500_000
MAX_ATTACHMENTS = 50
MAX_ATTACHMENT_NAME_LEN = 255

NameStr = Annotated[str, StringConstraints(max_length=MAX_NAME_LEN)]
AddressStr = Annotated[str, StringConstraints(max_length=MAX_ADDRESS_LEN)]
SubjectStr = Annotated[str, StringConstraints(max_length=MAX_SUBJECT_LEN)]
BodyPlainStr = Annotated[str, StringConstraints(max_length=MAX_BODY_PLAIN_LEN)]
BodyHtmlStr = Annotated[str, StringConstraints(max_length=MAX_BODY_HTML_LEN)]
AttachmentNameStr = Annotated[str, StringConstraints(max_length=MAX_ATTACHMENT_NAME_LEN)]

ScoreInt = Annotated[int, Field(ge=0, le=100)]


class EmailAnalyzeRequest(BaseModel):
    """Email metadata/content extracted by the Gmail Add-on."""

    model_config = ConfigDict(strict=True, extra="forbid")

    sender_name: Optional[NameStr] = None
    # Deliberately NOT EmailStr: malformed sender addresses are themselves a
    # signal we want to score, not a reason to reject the request.
    sender_email: AddressStr
    reply_to: Optional[AddressStr] = None
    subject: SubjectStr
    body_plain: Optional[BodyPlainStr] = None
    body_html: Optional[BodyHtmlStr] = None
    attachment_names: list[AttachmentNameStr] = Field(
        default_factory=list, max_length=MAX_ATTACHMENTS
    )


class EmailAnalyzeResponse(BaseModel):
    """Explainable risk assessment returned to the Add-on."""

    model_config = ConfigDict(strict=True, extra="forbid")

    score: ScoreInt
    verdict: Literal["Low", "Medium", "High", "Critical"]
    attack_type: str
    category_scores: dict[str, ScoreInt]
    findings: list[str]
    explanation: str
    recommendations: list[str]
