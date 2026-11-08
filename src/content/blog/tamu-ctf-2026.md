---
title: "TAMU CTF 2026 — web, audio, and signal-processing writeups"
ctf: "TAMU CTF 2026"
date: 2026-04-04
category: "Competition · Web, Audio Forensics, Signal Processing"
tags: ["tamu-ctf-2026", "web", "http3", "quic", "audio-forensics", "stft", "whisper"]
excerpt: "Three TAMU CTF 2026 solves: finding an HTTP/3-only origin, restoring shuffled audio, and reconstructing a voice flag from an STFT dump."
---

I solved three TAMU CTF 2026 challenges: Broken Website, Choppy, and numbers. They ended up being three different kinds of debugging—network transport, messy audio, and signal reconstruction.

## Web

### Broken Website

**Category:** Web · **Points:** 110  
**Result:** solved against the public challenge endpoint  
**Flag:** `gigem{7h3_fu7u23_15_qu1c_64d1f5}`

#### Start with the timeout, not the page

The page consistently timed out when accessed normally. The first useful question was whether the hostname pointed at a CDN, an origin, or a service that was not using TCP at all.

DNS showed an AWS address and Cloudflare nameservers, but the record was DNS-only rather than proxied. That distinction matters: the client was being sent directly to the EC2 origin instead of to Cloudflare's normal HTTP edge.

The TXT record tried to send me down a different path with a message aimed at language models. It was a red herring. The clues that mattered were the A record and the fact that Cloudflare proxying was disabled.

#### The transport clue is in `alt-svc`

TCP and UDP probing produced a confusing result: no useful TCP service appeared, while UDP 443 was open or filtered. A request through a Cloudflare anycast address returned a redirect with this header:

```http
alt-svc: h3=":443"; ma=86400
```

`h3` is HTTP/3. HTTP/3 runs over QUIC, and QUIC runs over UDP. This explains why a normal browser request and a TCP-only scan both looked broken: the origin was advertising a protocol most ordinary clients were not attempting directly.

The configuration can be summarized as:

```text
Cloudflare DNS-only
        ↓
direct EC2 origin
        ↓
Caddy serving HTTP/3 over UDP 443
```

The useful negative result was “TCP 443 is not the whole service.” A failed TCP connection only rules out an HTTP/1.1 or HTTP/2-over-TCP path. It says nothing about a QUIC listener on UDP/443. `alt-svc` is not proof that the origin is healthy, but it is a strong hint about which transport to try next.

#### Solver / Reproduction

I used the following sequence. Replace the host/IP only when working against the official challenge instance.

```sh
dig broken-website.tamuctf.cybr.club A
dig broken-website.tamuctf.cybr.club TXT
dig broken-website.tamuctf.cybr.club ANY

sudo nmap -Pn -sS -p- --open --min-rate 10000 54.91.191.64
curl -v -H "Host: broken-website.tamuctf.cybr.club" http://104.21.0.1/

curl -v --http3-only --insecure \
  --resolve broken-website.tamuctf.cybr.club:443:54.91.191.64 \
  https://broken-website.tamuctf.cybr.club/
```

The final request returned an HTTP/3 200 response from Caddy with the flag in the page body. The flag text, `the future is quic`, is also a hint toward the transport protocol.

#### What this teaches

`alt-svc` can reveal the transport when the page itself is unreachable. Here it exposed a UDP/QUIC path even though every TCP request failed.

## Audio Forensics

### Choppy

**Category:** Audio Forensics  
**Result:** reconstructed audio and decoded the spoken flag  
**Flag:** `gigem{slic3d&d1ced}`

#### The audio is shuffled, not destroyed

`choppy.wav` is 32 seconds long and sounds unintelligible after the first second. The spectrogram makes the structure much clearer: a diagonal sweep rises from roughly 2700 Hz to 6500 Hz, while the vocal material is still present underneath it.

The file is made of 128 chunks of 11,025 samples each, or 0.25 seconds at 44.1 kHz. The first second is unchanged; the remaining chunks are shuffled. Each chunk carries a tone whose frequency identifies the chunk's original position.

So I treated the first problem as sorting, not as trying to “restore” every clip:

```text
measure sweep frequency for each chunk
→ sort chunks by frequency
→ concatenate in sorted order
```

#### Solver / Reproduction

The core solver reads the WAV file, measures the strongest frequency in the 2–7 kHz band, sorts by that measurement, and writes an unscrambled file. A standalone copy is available as [`choppy_unscramble.py`](/solvers/tamu-ctf-2026/choppy_unscramble.py).

```sh
python3 choppy_unscramble.py choppy.wav choppy_unscrambled.wav
```

The ordering step is small:

```python
chunk_size = sr // 4

def dominant_freq(chunk, sr):
    fft = np.abs(np.fft.rfft(chunk))
    freqs = np.fft.rfftfreq(len(chunk), 1 / sr)
    mask = (freqs >= 2000) & (freqs <= 7000)
    return freqs[np.argmax(fft * mask)]

order = np.argsort([
    dominant_freq(data[i * chunk_size:(i + 1) * chunk_size], sr)
    for i in range(128)
])
pieces = [data[i * chunk_size:(i + 1) * chunk_size] for i in order]
wav.write(output, sr, np.concatenate(pieces).astype(np.int32))
```

The reconstructed audio still contains the sweep, so the source writeup separates vocals with Demucs:

```sh
python3 -m pip install demucs openai-whisper
demucs --two-stems=vocals choppy_unscrambled.wav
whisper separated/htdemucs/choppy_unscrambled/vocals.wav --language English
```

Whisper spells the flag character by character. The final `&` is read as “ampersand”, giving `gigem{slic3d&d1ced}`.

The frequency marker works because a 0.25-second chunk gives a fine enough FFT grid to order the sweep, while the vocal signal is spread over many bins. I did not need to identify the exact tone formula; the relative order of the dominant bins was enough. That is a useful general trick for shuffled media: look for a feature that changes monotonically with position, rather than trying to recognize the content of every piece.

#### Why the obvious filters were not enough

A normal band-pass filter cannot cleanly remove the sweep because it overlaps the vocal frequency range. Demucs works better here because it separates the vocal stem from the learned structure of the recording instead of deleting one fixed frequency band. The notes also show that aggressive enhancement changed the flag, so keeping the audio close to the original was the safer choice.

## Signal Processing

### numbers

**Category:** Misc / Signal Processing  
**Result:** reconstructed the audio and recovered the lowercase flag  
**Flag:** `gigem{fft_is_50_0p}`

#### The first line gives away the representation

The attachment starts with:

```text
# STFT shape: complex64 (129, 1380)
```

That is 178,020 complex values, exactly `129 × 1380`: a Short-Time Fourier Transform of an audio signal.

The imaginary component matters. The source notes count 165,481 non-zero imaginary values, so parsing only the real part would throw away most of the phase information needed by the inverse transform.

#### Match the encoder's conventions

The dump was generated with Nils Werner's `stft` library. SciPy's `istft` defaults use different conventions, so the reconstruction has to match:

```text
frame length = (129 - 1) × 2 = 256
overlap      = 2
hop          = 128
window       = scipy cosine window
halved       = true
centered     = true
```

The shape also tells us how to rebuild the missing half of each spectrum. For a real-valued signal, the negative-frequency bins are the complex conjugates of the positive-frequency bins. The solver mirrors `bins[1:-1]` in reverse order; duplicating the DC or Nyquist bins would create the wrong frame length and audible artifacts.

Using overlap 4 or dropping the imaginary part produces an audio file, but not the right one. This is a classic format-compatibility problem: the inverse transform is only correct when its framing and window assumptions match the encoder.

#### Solver / Reproduction

The full reconstruction script is [`numbers_reconstruct.py`](/solvers/tamu-ctf-2026/numbers_reconstruct.py). It parses the complex text, mirrors the positive-frequency bins, performs overlap-add normalization, removes the center padding, and writes `flag.wav`.

```sh
python3 numbers_reconstruct.py numbers.txt flag.wav
whisper flag.wav --language English
```

The reconstruction core is:

```python
full_spec = np.concatenate([frame_spec, np.conj(frame_spec[-2:0:-1])])
frame_time = np.real(scipy.fftpack.ifft(full_spec))
frame_win = frame_time * window
out[start:start + framelength] += frame_win
win_sq[start:start + framelength] += window ** 2

out[nz] /= win_sq[nz]
```

The clearest transcription from the recovered audio was:

```text
GIGEM left curly bracket FFT underscore I S underscore 5 0 underscore 0 P right curly bracket
```

Normalizing the case and punctuation gives the flag above.

The overlap-add normalization is not optional. Each sample is covered by several windowed frames, and the number of overlaps changes near the edges. Dividing by the accumulated squared window reconstructs the original amplitude instead of leaving a periodic volume pattern. I also keep the center-padding removal in the script because the encoder padded before the STFT; omitting it shifts the spoken text and makes transcription needlessly ambiguous.

#### What this teaches

For signal-processing challenges, comments describing array shape and the exact generating library are often more valuable than the raw sample values. Reconstructing the inverse transform is mostly a matter of preserving complex phase and matching the original framing convention.

## Source

These notes were expanded from the original files in [`dat-nix/writeup-ctf-2026`](https://github.com/dat-nix/writeup-ctf-2026/tree/main/TAMUctf). The flags and recorded observations are preserved; the structure adds explicit reasoning and reproduction boundaries.
