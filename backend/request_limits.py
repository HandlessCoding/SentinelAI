"""Bound JSON bodies before FastAPI decodes them."""

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute


MAX_JSON_BYTES = 2 * 1024 * 1024
SIZE_ERROR = "JSON request bodies must be at most 2 MiB."


class JSONRequestRoute(APIRoute):
    """Require explicit JSON and bound the total bytes delivered by ASGI."""

    def get_route_handler(self):
        handle = super().get_route_handler()
        if self.body_field is None:
            return handle

        async def limited_handler(request: Request):
            media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            encoding = request.headers.get("content-encoding", "identity").strip().lower()
            if media_type != "application/json" or encoding != "identity":
                raise HTTPException(
                    status_code=415,
                    detail="Send an uncompressed request with Content-Type application/json.",
                )

            lengths = request.headers.getlist("content-length")
            if lengths:
                declared_length = lengths[0].strip()
                if len(lengths) != 1 or not declared_length.isascii() or not declared_length.isdecimal():
                    raise HTTPException(status_code=400, detail="Invalid request length.")
                try:
                    declared_bytes = int(declared_length)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid request length.") from None
                if declared_bytes > MAX_JSON_BYTES:
                    raise HTTPException(status_code=413, detail=SIZE_ERROR)

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
