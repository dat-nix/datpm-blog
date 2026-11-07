#!/usr/bin/env python3
"""Static solver for the HTB reverse-engineering challenge CorpSyncAudit.

Usage:
    python3 corpsyncaudit_solve.py CorpSyncAudit.zip
    python3 corpsyncaudit_solve.py rev_CorpSyncAudit/

The script never executes the Windows binary or decoded shellcode.
"""

from __future__ import annotations

import argparse
import base64
import re
import struct
import sys
import zipfile
from pathlib import Path

IMAGE_BASE = 0x140000000
REGION_HASH_TABLE_RVA = 0x1D680
REGION_COUNT = 32
KNOWN_X64_STAGE_PREFIX = bytes.fromhex("fc4883e4")  # cld; and rsp, -16
MASK64 = (1 << 64) - 1

DATE_RECORD = re.compile(
    r"^(\w+), (\d{2})/(\d{2})/(\d{4}) "
    r"(\d{2}):(\d{2}):(\d{2}) (AM|PM) (UTC|GMT) "
    r"\| Region=([A-Z_]+)$"
)

WEEKDAY_KEY = {
    "Monday": 1,
    "Tuesday": 2,
    "Wednesday": 3,
    "Thursday": 4,
    "Friday": 5,
    "Saturday": 6,
    "Sunday": 7,
}


def ror64(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & MASK64


def region_hash(text: str) -> int:
    """Reimplementation of the binary's case-insensitive export-style hash."""
    value = 0xCBF29CE484222325
    for byte in text.encode("ascii"):
        if ord("a") <= byte <= ord("z"):
            byte -= 0x20
        value ^= byte
        value = (value * 0x100000001B3) & MASK64
        value = ror64(value, 13)

    value ^= value >> 33
    value = (value * 0xFF51AFD7ED558CCD) & MASK64
    value ^= value >> 33
    value = (value * 0xC4CEB9FE1A85EC53) & MASK64
    value ^= value >> 33
    return value


def pe_rva_to_offset(pe: bytes, rva: int) -> int:
    if pe[:2] != b"MZ":
        raise ValueError("input executable is not a PE file")

    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")

    coff = pe_offset + 4
    section_count = struct.unpack_from("<H", pe, coff + 2)[0]
    optional_size = struct.unpack_from("<H", pe, coff + 16)[0]
    section_table = coff + 20 + optional_size

    for index in range(section_count):
        off = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", pe, off + 8
        )
        mapped_size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + mapped_size:
            return raw_offset + (rva - virtual_address)

    raise ValueError(f"RVA 0x{rva:x} is not mapped by a PE section")


def cxx_div2(value: int) -> int:
    """C/C++ signed division by two, truncated toward zero."""
    return int(value / 2)


def decode_record(line: str, region_indices: dict[str, int]) -> bytes:
    match = DATE_RECORD.match(line)
    if not match:
        raise ValueError(f"not a payload record: {line!r}")

    weekday, day, month, year, hour, minute, second, _ampm, timezone, region = (
        match.groups()
    )
    day, month, year, hour, minute, second = map(
        int, (day, month, year, hour, minute, second)
    )

    # The hidden parser mutates GMT records before packing them.
    if timezone == "GMT":
        old_minute = minute
        adjustment = cxx_div2(hour + minute - second)
        hour -= adjustment
        minute = adjustment
        second = old_minute - adjustment

    region_index = region_indices[region]
    bits = f"{region_index:05b}"

    if bits[0] == "1":
        hour ^= 12
    if bits[1] == "1":
        minute ^= 30
    if bits[2] == "1":
        second ^= 30
    if bits[3] == "1":
        day ^= 16
    if bits[4] == "1":
        month ^= 6

    packed = (
        (hour << 27)
        | (minute << 21)
        | (second << 15)
        | (day << 10)
        | (month << 6)
        | (year - 1990)
    ) & 0xFFFFFFFF

    weekday_xor = WEEKDAY_KEY[weekday]
    return bytes(byte ^ weekday_xor for byte in packed.to_bytes(4, "big"))


def load_challenge(path: Path) -> tuple[bytes, list[tuple[str, bytes]]]:
    if path.is_file() and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            exe_names = [name for name in archive.namelist() if name.lower().endswith(".exe")]
            log_names = [name for name in archive.namelist() if name.lower().endswith(".log")]
            if len(exe_names) != 1:
                raise ValueError(f"expected one executable, found {len(exe_names)}")
            pe = archive.read(exe_names[0])
            logs = [(Path(name).name, archive.read(name)) for name in log_names]
            return pe, logs

    if path.is_dir():
        exe_files = list(path.rglob("*.exe"))
        log_files = list(path.rglob("*.log"))
        if len(exe_files) != 1:
            raise ValueError(f"expected one executable, found {len(exe_files)}")
        return exe_files[0].read_bytes(), [(file.name, file.read_bytes()) for file in log_files]

    raise ValueError("input must be the challenge ZIP or extracted directory")


def extract_flag(stage: bytes) -> tuple[str, str]:
    command_match = re.search(rb"net user [^\x00\r\n]+", stage)
    if not command_match:
        raise ValueError("decoded stage does not contain the expected net-user command")
    command = command_match.group().decode("ascii")

    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", command):
        try:
            decoded = base64.b64decode(token, validate=True).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        flag_match = re.search(r"HTB\{[^}]+\}", decoded)
        if flag_match:
            return command, flag_match.group()

    raise ValueError("no Base64-encoded HTB flag found in the command")


def solve(path: Path, output_stage: Path | None) -> None:
    pe, logs = load_challenge(path)
    if not logs:
        raise ValueError("no log files found")

    # The malicious journal is the only one carrying dozens of date records.
    scored_logs: list[tuple[int, str, str]] = []
    for name, raw in logs:
        text = raw.decode("ascii", errors="strict").replace("\r\n", "\n")
        score = sum(DATE_RECORD.match(line) is not None for line in text.splitlines())
        scored_logs.append((score, name, text))
    record_count, log_name, malicious_log = max(scored_logs)
    if record_count < 20:
        raise ValueError("could not identify the encoded second-stage log")

    table_offset = pe_rva_to_offset(pe, REGION_HASH_TABLE_RVA)
    region_table = list(struct.unpack_from(f"<{REGION_COUNT}Q", pe, table_offset))

    region_names = {
        match.group(10)
        for line in malicious_log.splitlines()
        if (match := DATE_RECORD.match(line))
    }
    region_indices: dict[str, int] = {}
    for region in region_names:
        digest = region_hash(region)
        try:
            region_indices[region] = region_table.index(digest)
        except ValueError as exc:
            raise ValueError(f"region {region!r} is absent from the embedded hash table") from exc

    pre_key = bytearray()
    for line in malicious_log.splitlines():
        if DATE_RECORD.match(line):
            pre_key.extend(decode_record(line, region_indices))

    if len(pre_key) < len(KNOWN_X64_STAGE_PREFIX):
        raise ValueError("encoded stage is too short")
    stage_xor_key = bytes(
        pre_key[index] ^ KNOWN_X64_STAGE_PREFIX[index]
        for index in range(len(KNOWN_X64_STAGE_PREFIX))
    )
    stage = bytes(
        byte ^ stage_xor_key[index % len(stage_xor_key)]
        for index, byte in enumerate(pre_key)
    )
    if not stage.startswith(KNOWN_X64_STAGE_PREFIX):
        raise ValueError("failed to recover the second-stage XOR key")
    command, flag = extract_flag(stage)

    if output_stage is not None:
        output_stage.write_bytes(stage)

    print(f"Encoded log : {log_name}")
    print(f"Records     : {record_count}")
    print(f"Stage size  : {len(stage)} bytes")
    print(f"XOR key     : {stage_xor_key.hex()}")
    print(f"Command     : {command}")
    print(f"Flag        : {flag}")
    if output_stage is not None:
        print(f"Stage saved : {output_stage}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge", type=Path, help="challenge ZIP or extracted directory")
    parser.add_argument(
        "--write-stage",
        type=Path,
        metavar="FILE",
        help="optionally write the decoded shellcode without executing it",
    )
    args = parser.parse_args()

    try:
        solve(args.challenge, args.write_stage)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
