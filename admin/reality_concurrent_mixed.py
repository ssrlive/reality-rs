#!/usr/bin/env python3
"""
Concurrent mixed-site pressure test for AnyTLS REALITY client/server
Usage: python admin/reality_concurrent_mixed.py --socks-proxy 127.0.0.1:1081 --total-requests 25

This script only runs curl-based pressure tests and assumes the
server and client are already running and reachable at the usual
addresses (server: 127.0.0.1:9445, client SOCKS5 proxy provided).
"""
from __future__ import annotations
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

TARGETS: List[str] = [
    "https://www.sina.com.cn/",
    "https://www.qq.com/",
    "https://www.baidu.com/",
    "https://www.bing.com/",
    "https://www.sohu.com/",
]


def run_curl(socks: str, target: str, timeout: int = 30) -> int:
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--socks5-hostname",
        socks,
        target,
    ]
    return subprocess.run(cmd).returncode


def bootstrap(socks: str) -> bool:
    # Try up to 15 attempts, rotating targets
    for attempt in range(15):
        target = TARGETS[attempt % len(TARGETS)]
        rc = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--retry",
                "5",
                "--retry-connrefused",
                "--retry-all-errors",
                "--socks5-hostname",
                socks,
                target,
            ]
        ).returncode
        if rc == 0:
            return True
    return False


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--socks-proxy", default="127.0.0.1:3080")
    p.add_argument("--total-requests", default=25, type=int)
    p.add_argument("--throttle-limit", default=10, type=int)
    p.add_argument("--timeout", default=30, type=int)
    args = p.parse_args()

    socks = args.socks_proxy
    total = args.total_requests
    throttle = args.throttle_limit
    timeout = args.timeout

    print(f"Bootstrap: checking proxy {socks} up to 15 attempts...")
    if not bootstrap(socks):
        print("bootstrap request failed")
        return 2
    print("bootstrap ok")

    results = []
    with ThreadPoolExecutor(max_workers=throttle) as ex:
        futures = {}
        for i in range(1, total + 1):
            target = TARGETS[(i - 1) % len(TARGETS)]
            fut = ex.submit(run_curl, socks, target, timeout)
            futures[fut] = (i, target)

        for fut in as_completed(futures):
            idx, tgt = futures[fut]
            try:
                rc = fut.result()
            except Exception:
                rc = 1
            results.append({"Index": idx, "Target": tgt, "ExitCode": rc})

    failed = [r for r in results if r["ExitCode"] != 0]

    # Counters for created/reused/timeouts require reading client logs; not available here.
    created = 0
    reused = 0
    wait_timeouts = 0

    print(f"concurrent multi-site results: total={len(results)} failed={len(failed)} created={created} reused={reused} waitTimeouts={wait_timeouts}")
    print("targets=" + ", ".join(TARGETS))

    if failed:
        print("Failed requests:")
        for r in sorted(failed, key=lambda x: x["Index"]):
            print(f"{r['Index']:3d}  {r['Target']:40s}  exit={r['ExitCode']}")
        print(f"concurrent multi-site curl failures: {len(failed)}")
        return 1

    print(f"concurrent multi-site pressure ok ({len(results)} total, throttle {throttle})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
