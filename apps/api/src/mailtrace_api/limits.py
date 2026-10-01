from starlette.responses import JSONResponse

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = 12 * 1024 * 1024
MAX_LAB_REQUEST_BYTES = 52 * 1024 * 1024


class RequestBodyLimit:
    """Bound actual bytes before JSON or multipart parsers consume them."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def no_store(message):
            if message["type"] == "http.response.start":
                message["headers"] = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control"]
                message["headers"].append((b"cache-control", b"no-store"))
            await send(message)

        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, no_store)
        length = next((v for k, v in scope.get("headers", []) if k.lower() == b"content-length"), None)
        maximum = MAX_LAB_REQUEST_BYTES if scope.get("path", "").startswith("/api/v1/lab/") else MAX_REQUEST_BYTES
        label = "52" if maximum == MAX_LAB_REQUEST_BYTES else "12"
        bound = str(maximum).encode("ascii")
        if length is not None:
            normalized_length = length.lstrip(b"0") or b"0"
            invalid = (not length.isdigit() or len(normalized_length) > len(bound)
                       or (len(normalized_length) == len(bound) and normalized_length > bound))
            if invalid:
                response = JSONResponse({"detail": f"请求体超过 {label} MiB 上限或长度无效。"}, status_code=413)
                return await response(scope, receive, no_store)
        messages = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > maximum:
                response = JSONResponse({"detail": f"请求体超过 {label} MiB 上限。"}, status_code=413)
                return await response(scope, receive, no_store)
            messages.append(message)
            if not message.get("more_body", False):
                break
        iterator = iter(messages)

        async def replay():
            return next(iterator, {"type": "http.request", "body": b"", "more_body": False})

        await self.app(scope, replay, no_store)
