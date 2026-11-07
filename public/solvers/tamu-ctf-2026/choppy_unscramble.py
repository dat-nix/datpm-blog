#!/usr/bin/env python3
"""Restore TAMU CTF 2026's shuffled choppy.wav."""

import argparse

import numpy as np
from scipy.io import wavfile


def dominant_frequency(chunk: np.ndarray, sample_rate: int) -> float:
    spectrum = np.abs(np.fft.rfft(chunk))
    frequencies = np.fft.rfftfreq(len(chunk), 1 / sample_rate)
    mask = (frequencies >= 2000) & (frequencies <= 7000)
    return float(frequencies[np.argmax(spectrum * mask)])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="shuffled WAV file")
    parser.add_argument("output", help="restored WAV file")
    args = parser.parse_args()

    sample_rate, data = wavfile.read(args.input)
    if data.ndim != 1:
        raise ValueError("expected a mono WAV file")

    chunk_size = sample_rate // 4
    chunk_count = len(data) // chunk_size
    chunks = [data[i * chunk_size:(i + 1) * chunk_size] for i in range(chunk_count)]
    frequencies = [dominant_frequency(chunk.astype(np.float64), sample_rate) for chunk in chunks]
    order = np.argsort(frequencies)
    restored = np.concatenate([chunks[i] for i in order])
    wavfile.write(args.output, sample_rate, restored)


if __name__ == "__main__":
    main()
