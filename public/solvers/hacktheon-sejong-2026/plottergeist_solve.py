#!/usr/bin/env python3

from __future__ import annotations

import argparse
import struct
import wave
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw


@dataclass
class UdpPacket:
    ts: float
    payload: bytes
    src: str
    dst: str
    sport: int
    dport: int


@dataclass
class MotionEvent:
    ts: float
    seq: int
    dt: int
    am: int
    bm: int
    duration: float = 0.0
    row: int = 0
    is_reset: bool = False


@dataclass
class Candidate:
    name: str
    bitmap: np.ndarray
    score: float
    fill_ratio: float
    blank_ratio: float


def signed_u16(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    return value - 65536 if value >= 32768 else value


def parse_pcap_packets(path: Path) -> list[UdpPacket]:
    data = path.read_bytes()
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("Unsupported pcap format")

    offset = 24
    packets: list[UdpPacket] = []

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len

        if len(frame) < 42 or frame[12:14] != b"\x08\x00":
            continue

        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17:
            continue

        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        udp = ip[ihl:]
        sport = int.from_bytes(udp[0:2], "big")
        dport = int.from_bytes(udp[2:4], "big")
        udp_len = int.from_bytes(udp[4:6], "big")
        payload = udp[8 : 8 + udp_len - 8]

        packets.append(
            UdpPacket(
                ts=ts_sec + ts_usec / 1_000_000.0,
                payload=payload,
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
            )
        )

    return packets


def extract_format_hints(packets: list[UdpPacket]) -> list[str]:
    hints: list[str] = []
    for packet in packets:
        payload = packet.payload
        if payload.startswith(b"\xc1") and payload.endswith(b"\x7e"):
            try:
                hints.append(payload[1:-1].decode("ascii"))
            except UnicodeDecodeError:
                pass
    return hints


def extract_motion_events(packets: list[UdpPacket]) -> list[MotionEvent]:
    events: list[MotionEvent] = []
    for packet in packets:
        payload = packet.payload
        if not payload.startswith(b"\xa1") or len(payload) < 9:
            continue
        events.append(
            MotionEvent(
                ts=packet.ts,
                seq=int.from_bytes(payload[1:3], "big"),
                dt=int.from_bytes(payload[3:5], "big"),
                am=signed_u16(payload[5:7]),
                bm=signed_u16(payload[7:9]),
            )
        )

    for idx, event in enumerate(events):
        if idx + 1 < len(events):
            event.duration = events[idx + 1].ts - event.ts
        else:
            event.duration = 0.06

    row = 0
    for event in events:
        if event.dt == 24:
            event.row = row
            event.is_reset = True
            row += 1
        else:
            event.row = row

    return events


def split_scanlines(events: list[MotionEvent]) -> list[list[MotionEvent]]:
    row_count = max(event.row for event in events if not event.is_reset) + 1
    rows: list[list[MotionEvent]] = [[] for _ in range(row_count)]
    for event in events:
        if not event.is_reset:
            rows[event.row].append(event)
    return rows


def load_audio(path: Path) -> tuple[np.ndarray, int]:
    with wave.open(str(path), "rb") as wav:
        if wav.getnchannels() != 1 or wav.getsampwidth() != 2:
            raise ValueError("Expected 16-bit mono WAV")
        rate = wav.getframerate()
        audio = np.frombuffer(wav.readframes(wav.getnframes()), dtype="<i2")
    return audio.astype(np.float32) / 32768.0, rate


def compute_audio_features(
    events: list[MotionEvent], audio: np.ndarray, sample_rate: int, offset_ms: int
) -> dict[tuple[int, int], dict[str, float]]:
    features: dict[tuple[int, int], dict[str, float]] = {}
    for event in events:
        start = int(round((event.ts + offset_ms / 1000.0) * sample_rate))
        start = max(start, 0)
        length = max(80, int(round(min(event.duration, 0.09) * sample_rate * 0.5)))
        segment = audio[start : start + length]
        if len(segment) < length:
            segment = np.pad(segment, (0, length - len(segment)))

        window = np.hanning(length)
        spectrum = np.abs(np.fft.rfft(segment * window)) ** 2
        freqs = np.fft.rfftfreq(length, 1.0 / sample_rate)

        bands = []
        for lo, hi in [(0, 300), (300, 700), (700, 1200), (1200, 2200), (2200, 3900)]:
            mask = (freqs >= lo) & (freqs < hi)
            bands.append(float(spectrum[mask].sum()))
        total = sum(bands) + 1e-12
        ratios = [band / total for band in bands]

        useful = (freqs > 50) & (freqs < 3500)
        dominant = float(freqs[useful][np.argmax(spectrum[useful])])

        features[(event.row, event.seq)] = {
            "pf": dominant,
            "b3": ratios[3],
            "hi_lo": float(np.log((ratios[3] + ratios[4] + 1e-9) / (ratios[0] + ratios[1] + 1e-9))),
        }

    return features


def render_bitmap(
    rows: list[list[MotionEvent]],
    width: int,
    include_first_row: bool,
    fill_rule,
) -> np.ndarray:
    start_row = 0 if include_first_row else 1
    active_rows = rows[start_row:]
    bitmap = np.zeros((len(active_rows), width), dtype=np.uint8)

    for out_y, row in enumerate(active_rows):
        x = 0
        for idx, event in enumerate(sorted(row, key=lambda item: item.seq)):
            span = max(event.am, 0)
            if span and fill_rule(event, idx):
                bitmap[out_y, x : x + span] = 1
            x += span

    return bitmap


def build_candidates(
    rows: list[list[MotionEvent]], events: list[MotionEvent], width: int, audio: np.ndarray, sample_rate: int
) -> list[Candidate]:
    candidates: list[Candidate] = []

    def add_candidate(name: str, bitmap: np.ndarray) -> None:
        if bitmap.size == 0:
            return
        fill_ratio = float(bitmap.mean())
        if fill_ratio < 0.03 or fill_ratio > 0.90:
            return
        blank_ratio = float((bitmap.sum(axis=0) == 0).mean())
        transitions = float(np.abs(np.diff(bitmap, axis=1)).mean()) if bitmap.shape[1] > 1 else 0.0
        score = blank_ratio - abs(fill_ratio - 0.28) - 0.20 * transitions
        candidates.append(
            Candidate(
                name=name,
                bitmap=bitmap,
                score=score,
                fill_ratio=fill_ratio,
                blank_ratio=blank_ratio,
            )
        )

    for include_first_row in [True, False]:
        suffix = "7r" if include_first_row else "6r"
        add_candidate(
            f"baseline_dt4_{suffix}",
            render_bitmap(rows, width, include_first_row, lambda event, _idx: event.dt == 4),
        )
        add_candidate(
            f"baseline_dt5_{suffix}",
            render_bitmap(rows, width, include_first_row, lambda event, _idx: event.dt >= 5),
        )
        add_candidate(
            f"baseline_alt0_{suffix}",
            render_bitmap(rows, width, include_first_row, lambda _event, idx: idx % 2 == 0),
        )
        add_candidate(
            f"baseline_alt1_{suffix}",
            render_bitmap(rows, width, include_first_row, lambda _event, idx: idx % 2 == 1),
        )

    for offset_ms in [15, 18, 20, 22]:
        audio_features = compute_audio_features(events, audio, sample_rate, offset_ms)

        for feature_name in ["b3", "hi_lo", "pf"]:
            grouped_all: dict[tuple[int, int], list[float]] = defaultdict(list)
            grouped_dt5: dict[int, list[float]] = defaultdict(list)
            by_dt: dict[int, list[float]] = defaultdict(list)

            for event in events:
                value = audio_features[(event.row, event.seq)][feature_name]
                grouped_all[(event.dt, event.am)].append(value)
                by_dt[event.dt].append(value)
                if event.dt >= 5:
                    grouped_dt5[event.am].append(value)

            per_dt_median = {dt: float(np.median(values)) for dt, values in by_dt.items()}

            labels_all: dict[tuple[int, int], int] = {}
            labels_dt5: dict[tuple[int, int], int] = {}

            for event in events:
                value = audio_features[(event.row, event.seq)][feature_name]

                bucket_all = grouped_all[(event.dt, event.am)]
                threshold_all = (
                    float(np.median(bucket_all))
                    if len(bucket_all) >= 6
                    else per_dt_median[event.dt]
                )
                labels_all[(event.row, event.seq)] = int(value > threshold_all)

                if event.dt >= 5:
                    bucket_dt5 = grouped_dt5[event.am]
                    threshold_dt5 = (
                        float(np.median(bucket_dt5))
                        if len(bucket_dt5) >= 6
                        else per_dt_median[event.dt]
                    )
                    labels_dt5[(event.row, event.seq)] = int(value > threshold_dt5)

            for include_first_row in [True, False]:
                suffix = "7r" if include_first_row else "6r"
                for polarity in [0, 1]:
                    add_candidate(
                        f"audio_all_off{offset_ms}_{feature_name}_p{polarity}_{suffix}",
                        render_bitmap(
                            rows,
                            width,
                            include_first_row,
                            lambda event, _idx, labels=labels_all, p=polarity: labels[(event.row, event.seq)] ==
 p,
                        ),
                    )
                    add_candidate(
                        f"audio_dt5_off{offset_ms}_{feature_name}_p{polarity}_{suffix}",
                        render_bitmap(
                            rows,
                            width,
                            include_first_row,
                            lambda event, _idx, labels=labels_dt5, p=polarity: event.dt >= 5
                            and labels.get((event.row, event.seq)) == p,
                        ),
                    )

    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    return candidates


def small_preview(bitmap: np.ndarray, width: int) -> Image.Image:
    preview = Image.fromarray((255 - bitmap * 255).astype(np.uint8), "L")
    preview = preview.resize((width, bitmap.shape[0] * 6), resample=Image.Resampling.BOX)
    preview = preview.resize((width * 8, preview.height * 8), resample=Image.Resampling.NEAREST)
    return preview


def choose_showcase_candidates(candidates: list[Candidate], limit: int) -> list[Candidate]:
    by_name = {candidate.name: candidate for candidate in candidates}
    preferred_names = [
        "baseline_dt4_7r",
        "baseline_dt5_7r",
        "baseline_alt0_7r",
        "baseline_alt1_7r",
        "audio_all_off15_b3_p0_7r",
        "audio_all_off15_hi_lo_p0_7r",
        "audio_all_off18_b3_p0_7r",
        "audio_all_off18_hi_lo_p0_7r",
        "audio_all_off20_b3_p0_7r",
        "audio_all_off20_hi_lo_p0_7r",
        "audio_all_off22_b3_p0_7r",
        "audio_all_off22_hi_lo_p0_7r",
        "audio_dt5_off15_b3_p0_7r",
        "audio_dt5_off15_hi_lo_p0_7r",
        "audio_dt5_off18_b3_p0_7r",
        "audio_dt5_off18_hi_lo_p0_7r",
        "audio_dt5_off20_b3_p0_7r",
        "audio_dt5_off20_hi_lo_p0_7r",
        "audio_dt5_off22_b3_p0_7r",
        "audio_dt5_off22_hi_lo_p0_7r",
    ]

    chosen: list[Candidate] = []
    seen: set[str] = set()

    for name in preferred_names:
        candidate = by_name.get(name)
        if candidate and candidate.name not in seen:
            chosen.append(candidate)
            seen.add(candidate.name)
        if len(chosen) >= limit:
            return chosen

    for candidate in candidates:
        if candidate.name in seen:
            continue
        chosen.append(candidate)
        seen.add(candidate.name)
        if len(chosen) >= limit:
            break

    return chosen


def save_contact_sheet(candidates: list[Candidate], output_path: Path, limit: int = 24) -> None:
    chosen = choose_showcase_candidates(candidates, limit)
    previews = [(candidate, small_preview(candidate.bitmap, 90)) for candidate in chosen]

    cell_width = max(preview.width for _candidate, preview in previews) + 10
    cell_height = max(preview.height for _candidate, preview in previews) + 28
    columns = 2
    rows = (len(previews) + columns - 1) // columns

    sheet = Image.new("L", (columns * cell_width, rows * cell_height), 255)
    draw = ImageDraw.Draw(sheet)

    for index, (candidate, preview) in enumerate(previews):
        x = (index % columns) * cell_width
        y = (index // columns) * cell_height
        label = (
            f"{candidate.name} "
            f"score={candidate.score:.3f} "
            f"fill={candidate.fill_ratio:.2f} "
            f"blank={candidate.blank_ratio:.2f}"
        )
        draw.text((x, y), label, fill=0)
        sheet.paste(preview, (x, y + 14))

    sheet.save(output_path)


def save_top_candidates(candidates: list[Candidate], output_dir: Path, count: int = 8) -> None:
    for index, candidate in enumerate(choose_showcase_candidates(candidates, count)):
        preview = small_preview(candidate.bitmap, 160)
        safe_name = candidate.name.replace("/", "_")
        preview.save(output_dir / f"{index:02d}_{safe_name}.png")


def write_summary(
    output_path: Path,
    packets: list[UdpPacket],
    hints: list[str],
    events: list[MotionEvent],
    rows: list[list[MotionEvent]],
    candidates: list[Candidate],
) -> None:
    payload_lengths = Counter(len(packet.payload) for packet in packets)
    row_widths = [sum(max(event.am, 0) for event in row) for row in rows]
    reset_events = [event for event in events if event.is_reset]

    lines = []
    lines.append("plottergeist solver summary")
    lines.append("")
    lines.append(f"udp packets: {len(packets)}")
    lines.append(f"payload lengths: {dict(sorted(payload_lengths.items()))}")
    lines.append("")
    lines.append("format hints:")
    for hint in hints:
        lines.append(f"  - {hint}")
    lines.append("")
    lines.append(f"motion events: {len(events)}")
    lines.append(f"scanlines: {len(rows)}")
    lines.append(f"row widths: {row_widths}")
    lines.append("reset moves:")
    for event in reset_events:
        lines.append(
            f"  - row {event.row}: dt={event.dt} am={event.am} bm={event.bm} ts={event.ts:.6f}"
        )
    lines.append("")
    lines.append("selected candidates:")
    for candidate in choose_showcase_candidates(candidates, 12):
        lines.append(
            f"  - {candidate.name}: score={candidate.score:.4f}, "
            f"fill={candidate.fill_ratio:.3f}, blank={candidate.blank_ratio:.3f}"
        )
    lines.append("")
    lines.append(
        "Known final flag from manual reading of the recovered raster: "
        "hacktheon2026{the_plotter_reveals_its_secret_through_sound}"
    )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse the plottergeist pcap/WAV pair and generate candidate reconstructions."
    )
    parser.add_argument("--pcap", default="plottergeist.pcap", help="Path to the pcap capture")
    parser.add_argument("--wav", default="bench_mic.wav", help="Path to the bench microphone WAV")
    parser.add_argument(
        "--out-dir",
        default="solve_output",
        help="Directory where the contact sheet and candidate images will be written",
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    wav_path = Path(args.wav)
    output_dir = Path(args.out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    packets = parse_pcap_packets(pcap_path)
    hints = extract_format_hints(packets)
    events = extract_motion_events(packets)
    rows = split_scanlines(events)
    width = max(sum(max(event.am, 0) for event in row) for row in rows)
    audio, sample_rate = load_audio(wav_path)

    candidates = build_candidates(rows, [event for event in events if not event.is_reset], width, audio,
sample_rate)

    save_contact_sheet(candidates, output_dir / "contact_sheet.png")
    save_top_candidates(candidates, output_dir)
    write_summary(output_dir / "summary.txt", packets, hints, events, rows, candidates)

    print(f"[+] Wrote contact sheet to: {output_dir / 'contact_sheet.png'}")
    print(f"[+] Wrote top candidate previews to: {output_dir}")
    print(f"[+] Wrote summary to: {output_dir / 'summary.txt'}")
    if hints:
        print(f"[+] Found format hint: {hints[0]}")
    print(f"[+] Scanlines: {len(rows)}")
    print(f"[+] Row widths: {[sum(max(event.am, 0) for event in row) for row in rows]}")
    print("[+] Strong candidates usually come from the audio_* entries in the contact sheet.")


if __name__ == "__main__":
    main()
