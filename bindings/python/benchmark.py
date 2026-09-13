#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from sigil_tiktoken import Tokenizer


def load_corpus(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise SystemExit(f"corpus must be a JSON array of strings: {path}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the SIGIL Python tokenizer binding")
    parser.add_argument("--lib", type=Path, default=None, help="Path to libzig_tiktoken shared library")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "bench" / "corpora" / "stress.json",
        help="JSON corpus of strings",
    )
    parser.add_argument("--vocab", default="cl100k_base")
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--specials", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human output")
    args = parser.parse_args()

    corpus = load_corpus(args.corpus)
    if not corpus:
        raise SystemExit("corpus is empty")

    with Tokenizer.open(args.vocab, library_path=args.lib) as tokenizer:
        encode_times = []
        decode_times = []
        total_tokens = 0
        parity = True

        for _ in range(max(1, args.rounds)):
            start = time.perf_counter_ns()
            encoded = [tokenizer.encode(text) for text in corpus]
            encode_times.append(time.perf_counter_ns() - start)

            start = time.perf_counter_ns()
            decoded = [tokenizer.decode(ids) for ids in encoded]
            decode_times.append(time.perf_counter_ns() - start)

            parity = parity and all(decoded[i] == corpus[i] for i in range(len(corpus)))
            total_tokens += sum(len(ids) for ids in encoded)

        def ns_per_token(samples: list[int]) -> int:
            return int(statistics.mean(samples) / max(total_tokens, 1))

        result = {
            "language": "python",
            "vocab": args.vocab,
            "corpus": str(args.corpus),
            "rounds": max(1, args.rounds),
            "items": len(corpus),
            "total_tokens": total_tokens,
            "encode_ns_per_token": ns_per_token(encode_times),
            "decode_ns_per_token": ns_per_token(decode_times),
            "roundtrip_parity": parity,
            "specials": bool(args.specials),
        }

        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                "python binding benchmark\n"
                f"  vocab: {result['vocab']}\n"
                f"  corpus: {result['corpus']}\n"
                f"  rounds: {result['rounds']}\n"
                f"  items: {result['items']}\n"
                f"  total tokens: {result['total_tokens']}\n"
                f"  encode ns/token: {result['encode_ns_per_token']}\n"
                f"  decode ns/token: {result['decode_ns_per_token']}\n"
                f"  roundtrip parity: {result['roundtrip_parity']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
