"""MailGuard FastAPI backend.

Stateless: requests are analyzed in memory and never stored. Email content
and subjects must never be logged.
"""

import os
import secrets

from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.exceptions import RequestValidationError
from fastapi.security import APIKeyHeader
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.analyzer import analyze_email
from backend.schemas import EmailAnalyzeRequest, EmailAnalyzeResponse

MAX_REQUEST_BYTES = 1 * 1024 * 1024  # 1 MB

API_KEY_ENV_VAR = "MAILGUARD_API_KEY"


def _load_api_key() -> str:
    """Fail closed: refuse to start without an explicitly configured key.

    A built-in fallback key would silently ship a publicly known credential
    to any deployment that forgot to configure one.
    """
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if not key:
        raise RuntimeError(
            f"{API_KEY_ENV_VAR} is not set. Refusing to start without an API key; "
            f"set {API_KEY_ENV_VAR} to a long random secret."
        )
    return key


API_KEY = _load_api_key()


class MaxBodySizeMiddleware:
    """Reject request bodies larger than `max_bytes` with 413.

    Pure ASGI middleware. It rejects early on a declared Content-Length and
    also counts the bytes actually received, so chunked requests or a false
    Content-Length cannot get past the limit. At most max_bytes are buffered.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                declared_len = int(declared)
            except ValueError:
                await _error(scope, receive, send, status.HTTP_400_BAD_REQUEST, "Invalid Content-Length.")
                return
            if declared_len > self.max_bytes:
                await self._reject(scope, receive, send)
                return

        # Read the body ourselves (never more than max_bytes + one chunk), then
        # replay it to the app. This also covers chunked bodies with no Content-Length.
        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            received += len(body)
            if received > self.max_bytes:
                await self._reject(scope, receive, send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()  # later calls: wait for disconnect as usual

        await self.app(scope, replay_receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        await _error(scope, receive, send, status.HTTP_413_CONTENT_TOO_LARGE,
                     f"Request body exceeds {self.max_bytes} bytes.")


async def _error(scope: Scope, receive: Receive, send: Send, code: int, detail: str) -> None:
    await JSONResponse({"detail": detail}, status_code=code)(scope, receive, send)


_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(_api_key_header)) -> None:
    # Constant-time comparison so the key cannot be guessed from response timing.
    if not api_key or not secrets.compare_digest(api_key.encode(), API_KEY.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


app = FastAPI(
    title="MailGuard",
    description="Explainable, deterministic malicious email scorer.",
    version="0.1.0",
    # Don't publish the API schema or interactive docs on a public endpoint.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(MaxBodySizeMiddleware, max_bytes=MAX_REQUEST_BYTES)

MAX_REPORTED_ERRORS = 20


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """422 that names WHERE and WHAT KIND of error only.

    FastAPI's default handler echoes the offending `input` (and `ctx`) back,
    which would return email content in the response, and into any proxy or
    gateway that logs responses.
    """
    errors = [
        {
            "loc": [part if isinstance(part, int) else str(part)[:64] for part in err.get("loc", ())],
            "type": str(err.get("type", "value_error")),
        }
        for err in exc.errors()[:MAX_REPORTED_ERRORS]
    ]
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": errors})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=EmailAnalyzeResponse,
    dependencies=[Depends(require_api_key)],
)
def analyze(request: EmailAnalyzeRequest) -> EmailAnalyzeResponse:
    return analyze_email(request)
