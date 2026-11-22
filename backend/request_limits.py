"""Bound JSON bodies before FastAPI decodes them."""

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute

MAX_JSON_BYTES = 2 * 1024 * 1024
SIZE_ERROR = "JSON request bodies must be at most 2 MiB."


def validate_body_headers(request, *, media_type, max_bytes, media_error, length_error, size_error):
    """Validate headers before reading an uncompressed request body."""
    types = request.headers.getlist("content-type")
    encodings = request.headers.getlist("content-encoding")
    if (len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != media_type
            or len(encodings) > 1 or (encodings and encodings[0].strip().lower() != "identity")):
        raise HTTPException(status_code=415, detail=media_error)

    lengths = request.headers.getlist("content-length")
    if not lengths:
        return
    length = lengths[0].strip()
    if len(lengths) != 1 or not length.isascii() or not length.isdecimal():
        raise HTTPException(status_code=400, detail=length_error)
    try:
        declared_bytes = int(length)
    except ValueError:
        raise HTTPException(status_code=400, detail=length_error) from None
    if declared_bytes > max_bytes:
        raise HTTPException(status_code=413, detail=size_error)


class JSONRequestRoute(APIRoute):
    """Require explicit JSON and bound the total bytes delivered by ASGI."""

    def get_route_handler(self):
        handle = super().get_route_handler()
        if self.body_field is None:
            return handle

        async def limited_handler(request: Request):
            validate_body_headers(
                request, media_type="application/json", max_bytes=MAX_JSON_BYTES,
                media_error="Send an uncompressed request with Content-Type application/json.",
                length_error="Invalid request length.", size_error=SIZE_ERROR,
            )

            received_bytes = 0
            original_receive = request.receive

            async def limited_receive():
                nonlocal received_bytes
                message = await original_receive()
                if message["type"] == "http.request":
                    received_bytes += len(message.get("body", b""))
                    if received_bytes > MAX_JSON_BYTES:
                        raise HTTPException(status_code=413, detail=SIZE_ERROR)
                return message

            return await handle(Request(request.scope, receive=limited_receive))

        return limited_handler
