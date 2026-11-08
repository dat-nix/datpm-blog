#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import tempfile
import wave
from pathlib import Path
from urllib.request import Request, urlopen

import imageio_ffmpeg
import numpy as np
import soundfile as sf


WORKDIR = Path(__file__).resolve().parent
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()


def http_json(url: str, data: bytes | None = None, headers: dict[str, str] | None = None):
    req = Request(url, data=data, headers=headers or {})
    with urlopen(req) as resp:
        return json.loads(resp.read().decode())


def get_challenge(base_url: str):
    return http_json(f"{base_url}/api/challenge")


def synthesize_mp3(text: str, out_path: Path, voice: str = "en-US-GuyNeural"):
    cmd = [
        sys.executable,
        "-m",
        "edge_tts",
        "-t",
        text,
        "-v",
        voice,
        "--write-media",
        str(out_path),
    ]
    subprocess.run(cmd, check=True, cwd=WORKDIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ffmpeg_to_wav(src: Path, dst: Path):
    cmd = [
        FFMPEG,
        "-y",
        "-i",
        str(src),
        "-ar",
        "16000",
        "-ac",
        "1",
        "-c:a",
        "pcm_s16le",
        str(dst),
    ]
    subprocess.run(cmd, check=True, cwd=WORKDIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_wav(path: Path):
    data, sr = sf.read(path, dtype="float32")
    if data.ndim > 1:
        data = data.mean(axis=1)
    return data, sr


def write_wav(path: Path, data: np.ndarray, sr: int = 16000):
    sf.write(path, data.astype(np.float32), sr, subtype="PCM_16")


def concat(paths: list[Path], out_path: Path):
    chunks = []
    sr = 16000
    for path in paths:
        data, sr = read_wav(path)
        chunks.append(data)
    write_wav(out_path, np.concatenate(chunks), sr)


def mix(weight_a: float, a_path: Path, b_path: Path, out_path: Path):
    a, sr = read_wav(a_path)
    b, _ = read_wav(b_path)
    n = max(len(a), len(b))
    aa = np.zeros(n, dtype=np.float32)
    bb = np.zeros(n, dtype=np.float32)
    aa[: len(a)] = a
    bb[: len(b)] = b
    out = weight_a * aa + (1.0 - weight_a) * bb
    peak = np.max(np.abs(out))
    if peak > 0.99:
        out = out / peak * 0.99
    write_wav(out_path, out, sr)


def multiple_data_chunks(first: Path, second: Path, out_path: Path):
    with first.open("rb") as fa, second.open("rb") as fb:
        a = fa.read()
        b = fb.read()

    if a[:4] != b"RIFF" or a[8:12] != b"WAVE" or b[:4] != b"RIFF" or b[8:12] != b"WAVE":
        raise ValueError("Need WAV inputs")

    def chunks(buf: bytes):
        pos = 12
        items = []
        while pos + 8 <= len(buf):
            chunk_id = buf[pos : pos + 4]
            size = int.from_bytes(buf[pos + 4 : pos + 8], "little")
            payload_start = pos + 8
            payload_end = payload_start + size
            items.append((chunk_id, buf[payload_start:payload_end]))
            pos = payload_end + (size & 1)
        return items

    a_chunks = chunks(a)
    b_chunks = chunks(b)
    fmt = next(payload for cid, payload in a_chunks if cid == b"fmt ")
    data_a = next(payload for cid, payload in a_chunks if cid == b"data")
    data_b = next(payload for cid, payload in b_chunks if cid == b"data")

    out = bytearray(b"RIFF\x00\x00\x00\x00WAVE")
    for cid, payload in [(b"fmt ", fmt), (b"data", data_a), (b"data", data_b)]:
        out += cid + len(payload).to_bytes(4, "little") + payload
        if len(payload) & 1:
            out += b"\x00"
    size = len(out) - 8
    out[4:8] = size.to_bytes(4, "little")
    out_path.write_bytes(out)


def verify(audio_path: Path, token: str, base_url: str):
    boundary = "----codexboundary"
    file_bytes = audio_path.read_bytes()
    parts = []
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="audio"; filename="{audio_path.name}"\r\n'
        f"Content-Type: audio/wav\r\n\r\n".encode()
        + file_bytes
        + b"\r\n"
    )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="token"\r\n\r\n{token}\r\n'.encode()
    )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    return http_json(
        f"{base_url}/api/verify",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )


def describe_wav(path: Path):
    with wave.open(str(path), "rb") as w:
        return {
            "frames": w.getnframes(),
            "sr": w.getframerate(),
            "channels": w.getnchannels(),
            "width": w.getsampwidth(),
            "duration": round(w.getnframes() / w.getframerate(), 3),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--voice", default="en-US-GuyNeural")
    parser.add_argument("--mode", choices=["plain", "concat", "mix", "multidata"], default="plain")
    parser.add_argument("--sample", default="sample_003.wav")
    parser.add_argument("--weight", type=float, default=0.8)
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    challenge = get_challenge(base_url)
    print(json.dumps(challenge, ensure_ascii=False, indent=2))
    token = challenge["token"]
    text = challenge["target_sentence"]

    with tempfile.TemporaryDirectory(dir=WORKDIR) as td:
        td = Path(td)
        mp3 = td / "tts.mp3"
        tts = td / "tts.wav"
        out = td / "candidate.wav"

        synthesize_mp3(text, mp3, voice=args.voice)
        ffmpeg_to_wav(mp3, tts)

        sample = WORKDIR / args.sample
        if args.mode == "plain":
            out.write_bytes(tts.read_bytes())
        elif args.mode == "concat":
            concat([sample, tts], out)
        elif args.mode == "mix":
            mix(args.weight, sample, tts, out)
        elif args.mode == "multidata":
            multiple_data_chunks(sample, tts, out)

        print(json.dumps({"candidate": str(out), "wav": describe_wav(out)}, indent=2))
        result = verify(out, token, base_url)
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
