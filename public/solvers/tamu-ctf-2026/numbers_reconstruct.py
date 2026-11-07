#!/usr/bin/env python3
"""Reconstruct TAMU CTF 2026's audio from the numbers.txt STFT dump."""

import argparse

import numpy as np
import scipy.fftpack
from scipy.io import wavfile


def parse_stft(path: str) -> np.ndarray:
    values = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            values.append(complex(line.replace(" ", "")))
    return np.asarray(values, dtype=np.complex64).reshape(129, 1380)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="numbers.txt")
    parser.add_argument("output", help="output WAV file")
    args = parser.parse_args()

    stft_data = parse_stft(args.input)
    frame_length = 256
    overlap = 2
    hop = frame_length // overlap
    window = np.sin(np.pi * (np.arange(frame_length) + 0.5) / frame_length)

    frame_count = stft_data.shape[1]
    output_length = (frame_count - 1) * hop + frame_length
    output = np.zeros(output_length, dtype=np.float64)
    window_squared = np.zeros(output_length, dtype=np.float64)

    for index in range(frame_count):
        positive = stft_data[:, index]
        full_spectrum = np.concatenate([positive, np.conj(positive[-2:0:-1])])
        frame = np.real(scipy.fftpack.ifft(full_spectrum))
        start = index * hop
        output[start:start + frame_length] += frame * window
        window_squared[start:start + frame_length] += window ** 2

    nonzero = window_squared > 1e-12
    output[nonzero] /= window_squared[nonzero]
    padding = frame_length // 2
    output = output[padding:-padding]
    output /= np.max(np.abs(output))
    wavfile.write(args.output, 22050, (output * 32767).astype(np.int16))


if __name__ == "__main__":
    main()
