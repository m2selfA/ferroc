#!/usr/bin/env python3
"""Fail closed on ELF ABI and real glibc 2.17 MCP roundtrip failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import uuid

RUNTIME_IMAGE = "quay.io/pypa/manylinux2014_x86_64@sha256:62eeff30ef134a85ec0f97109e008a319b0315ca5e8a6d754ee771556c02622a"
SENTINEL = "ferroc glibc 2.17 native roundtrip"
ALLOWED_LIBRARIES = {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libgcc_s.so.1", "ld-linux-x86-64.so.2"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_abi(versions, dynamic, headers):
    # Definitions are not requirements: only inspect the version-needs block.
    needs = versions.partition("Version needs section")[2]
    require(needs, "Missing ELF version-needs section")
    labels = set(re.findall(r"\bName:\s+(GLIBC_[A-Za-z0-9_.]+)", needs))
    require(labels, "Missing GLIBC version requirements")
    numbers = []
    for label in labels:
        suffix = label.removeprefix("GLIBC_")
        require(re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", suffix), f"Unsupported GLIBC requirement: {label}")
        version = tuple(map(int, suffix.split(".")))
        numbers.append(version + (0,) * (3 - len(version)))
    require(max(numbers) <= (2, 17, 0), f"Requires GLIBC newer than 2.17: {sorted(labels)}")
    libraries = set(re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic))
    require("libc.so.6" in libraries, "Expected a dynamically linked glibc executable")
    require(libraries <= ALLOWED_LIBRARIES, f"Unexpected runtime libraries: {sorted(libraries - ALLOWED_LIBRARIES)}")
    require(not re.search(r"\((?:RELR|RELRSZ|RELRENT)\)", dynamic), "DT_RELR needs a newer loader")
    interpreter = re.findall(r"Requesting program interpreter:\s*([^]\s]+)", headers)
    require(interpreter == ["/lib64/ld-linux-x86-64.so.2"], "Unexpected ELF interpreter")
    return {"glibcRequirements": sorted(labels), "neededLibraries": sorted(libraries), "interpreter": interpreter[0]}


def validate_rpc(stdout):
    replies = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    require([r.get("id") for r in replies] == [1, 2, 3, 4], "Unexpected MCP replies/order")
    require(all(r.get("jsonrpc") == "2.0" and "error" not in r for r in replies), "MCP protocol error")
    require(replies[0]["result"]["protocolVersion"] == "2025-06-18", "Protocol negotiation failed")
    tools = replies[1]["result"]["tools"]
    require(len(tools) == 25 and len({t["name"] for t in tools}) == 25, "Unexpected registered tool set")
    for reply in replies[2:]:
        require(reply["result"].get("isError") is not True, "Filesystem tool failed")
    content = replies[3]["result"]["content"]
    require(len(content) == 1 and content[0]["type"] == "text", "Unexpected read_file envelope")
    require(json.loads(content[0]["text"])["text"] == SENTINEL, "File roundtrip differs")


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60, **kwargs)


def verify(binary):
    header = binary.read_bytes()[:64]
    require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01", "Expected ELF64 little-endian")
    require(struct.unpack_from("<H", header, 18)[0] == 62, "Expected x86_64 ELF")
    env = dict(os.environ, LC_ALL="C")
    abi = parse_abi(*(run(["readelf", "--wide", flag, str(binary)], env=env).stdout for flag in ("--version-info", "--dynamic", "--program-headers")))
    subprocess.run(["docker", "pull", RUNTIME_IMAGE], check=True, timeout=600)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "write_file", "arguments": {"path": "/tmp/roundtrip.txt", "content": SENTINEL, "mode": "rewrite"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/tmp/roundtrip.txt"}}},
    ]
    container = "ferroc-compat-" + uuid.uuid4().hex
    script = 'v=$(getconf GNU_LIBC_VERSION); test "$v" = "glibc 2.17"; echo "FERROC_RUNTIME=$v" >&2; exec /verify/ferroc --allow-dir /tmp --no-transfers stdio'
    command = ["docker", "run", "--rm", "--name", container, "--network", "none", "--memory", "512m", "--pids-limit", "128", "-i", "--mount", f"type=bind,source={binary.parent},target=/verify,readonly", "--entrypoint", "/bin/bash", RUNTIME_IMAGE, "-ec", script]
    try:
        probe = run(command, input="".join(json.dumps(r) + "\n" for r in requests))
    except subprocess.TimeoutExpired:
        # Killing only the docker client could strand the actual test process.
        subprocess.run(["docker", "rm", "--force", container], check=True, timeout=30)
        raise
    require("FERROC_RUNTIME=glibc 2.17" in probe.stderr.splitlines(), "Runtime glibc readback missing")
    validate_rpc(probe.stdout)
    return {"passed": True, "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "abi": abi, "runtimeImage": RUNTIME_IMAGE, "runtimeGlibc": "2.17", "checks": ["ELF x86_64", "GLIBC requirements <= 2.17", "loader and shared libraries", "actual glibc readback", "stdio initialize/list25/write/read"], "boundary": "glibc userspace container on CI host kernel; not legacy-kernel or production qualification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        require(args.binary.name == "ferroc", "Runtime mount expects binary named ferroc")
        report = verify(args.binary.resolve(strict=True))
    except Exception as error:
        # A failed rerun must not leave an old passing receipt at the canonical path.
        args.report.write_text(json.dumps({"passed": False, "error": str(error)}, indent=2) + "\n", encoding="utf-8")
        raise
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
