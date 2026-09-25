"""Serve the repo so paper URLs work with or without the tutorials/ prefix.

Pages live in tutorials/<slug>/, while the nav used to point at /<slug>/.
A request for /2023_liu_forward_pass/ is served from tutorials/2023_liu_forward_pass/.
"""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
SLUGS = {
    path.name
    for path in (ROOT / "tutorials").iterdir()
    if path.is_dir() and path.name != "assets"
}


class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        url_path = unquote(urlparse(path).path)
        parts = [part for part in url_path.split("/") if part and part not in (".", "..")]
        if parts and parts[0] in SLUGS:
            url_path = "/tutorials/" + "/".join(parts)
            if path.split("?", 1)[0].endswith("/"):
                url_path += "/"
        return super().translate_path(url_path)


def main():
    handler = partial(Handler, directory=str(ROOT))
    server = ThreadingHTTPServer(("127.0.0.1", 8765), handler)
    print(f"serving {ROOT} at http://127.0.0.1:8765/")
    server.serve_forever()


if __name__ == "__main__":
    main()
