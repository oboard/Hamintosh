#!/usr/bin/env python3
"""Resume a stored IPSW ZIP member using parallel HTTP ranges and verify its CRC32."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import struct
import time
import urllib.request
import zlib


def fetch(url, start, end):
    request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(request, timeout=90) as response:
        content_range = response.headers.get("Content-Range", "")
        if response.status != 206 or not content_range.startswith(f"bytes {start}-{end}/"):
            raise ValueError(f"Server did not honor range {start}-{end}: {content_range}")
        result = response.read(end - start + 2)
        if len(result) != end - start + 1:
            raise ValueError("Truncated range response")
        return result


def locate(url, member, allow_deflate=False):
    request = urllib.request.Request(url, headers={"Range": "bytes=-131072"})
    with urllib.request.urlopen(request, timeout=90) as response:
        if response.status != 206:
            raise ValueError("HTTP range support is required")
        match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers["Content-Range"])
        if not match:
            raise ValueError("Invalid suffix range response")
        tail_start, end, total = map(int, match.groups())
        tail = response.read(131073)
        if len(tail) != end - tail_start + 1 or len(tail) > 131072:
            raise ValueError("Invalid ZIP tail length")
        identity = response.headers.get("ETag", "")
    at = tail.rfind(b"PK\x05\x06")
    if at < 0:
        raise ValueError("ZIP end record not found")
    size, offset = struct.unpack_from("<II", tail, at + 12)
    if offset == 0xFFFFFFFF or size == 0xFFFFFFFF:
        locator = at - 20
        if tail[locator:locator+4] != b"PK\x06\x07":
            raise ValueError("ZIP64 locator not found")
        z64 = struct.unpack_from("<Q", tail, locator + 8)[0]
        record = fetch(url, z64, z64 + 55)
        if record[:4] != b"PK\x06\x06":
            raise ValueError("Invalid ZIP64 end record")
        size, offset = struct.unpack_from("<QQ", record, 40)
    if size > 32 * 1024 * 1024:
        raise ValueError("ZIP directory exceeds metadata limit")
    directory = fetch(url, offset, offset + size - 1)
    at = 0
    while directory[at:at+4] == b"PK\x01\x02":
        flags, method = struct.unpack_from("<HH", directory, at + 8)
        crc, compressed, length = struct.unpack_from("<III", directory, at + 16)
        n, x, c = struct.unpack_from("<HHH", directory, at + 28)
        local = struct.unpack_from("<I", directory, at + 42)[0]
        name = directory[at+46:at+46+n].decode("utf-8")
        extra = directory[at+46+n:at+46+n+x]
        if name == member:
            pos = 0
            while pos + 4 <= len(extra):
                kind, count = struct.unpack_from("<HH", extra, pos)
                if kind == 1:
                    values = iter(struct.unpack("<" + "Q" * (count // 8), extra[pos+4:pos+4+count//8*8]))
                    if length == 0xFFFFFFFF: length = next(values)
                    if compressed == 0xFFFFFFFF: compressed = next(values)
                    if local == 0xFFFFFFFF: local = next(values)
                pos += 4 + count
            if flags & 1 or (method != 0 and not (allow_deflate and method == 8)) or (method == 0 and compressed != length):
                raise ValueError("Only uncompressed, unencrypted ZIP members are supported (AEA is supported as file data)")
            header = fetch(url, local, local + 29)
            if header[:4] != b"PK\x03\x04":
                raise ValueError("Invalid ZIP local header")
            name_size, extra_size = struct.unpack_from("<HH", header, 26)
            start = local + 30 + name_size + extra_size
            if start + compressed > total:
                raise ValueError("ZIP member exceeds archive bounds")
            result = {"url": url, "etag": identity, "member": member, "start": start,
                      "size": length, "crc32": crc}
            if method == 8:
                result.update({"method": method, "compressedSize": compressed})
            return result
        at += 46 + n + x + c
    raise ValueError(f"ZIP member not found: {member}")


def download(url, member, output, workers):
    meta = locate(url, member)
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_suffix(output.suffix + ".partial")
    checkpoint = output.with_suffix(output.suffix + ".progress.json")
    block = 4 * 1024 * 1024
    completed = set()
    if checkpoint.exists() and partial.exists():
        old = json.loads(checkpoint.read_text())
        if old["source"] != meta:
            raise ValueError("Existing partial download belongs to a different source")
        completed = set(old["completed"])
    fd = os.open(partial, os.O_RDWR | os.O_CREAT, 0o600)
    os.ftruncate(fd, meta["size"])
    count = (meta["size"] + block - 1) // block

    def chunk(index):
        begin = index * block
        size = min(block, meta["size"] - begin)
        for attempt in range(4):
            try:
                data = fetch(url, meta["start"] + begin, meta["start"] + begin + size - 1)
                written = 0
                while written < len(data):
                    n = os.pwrite(fd, data[written:], begin + written)
                    if n <= 0: raise OSError("Short download file write")
                    written += n
                return index
            except Exception:
                if attempt == 3: raise
                time.sleep(2 ** attempt)

    print(f"Downloading {member}: {meta['size'] / 1024**3:.2f} GiB; resume {len(completed)}/{count}", flush=True)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            jobs = [pool.submit(chunk, i) for i in range(count) if i not in completed]
            for job in as_completed(jobs):
                completed.add(job.result())
                checkpoint.write_text(json.dumps({"source": meta, "completed": sorted(completed)}))
                if len(completed) % 16 == 0 or len(completed) == count:
                    print(f"{len(completed)}/{count} blocks ({100 * len(completed)/count:.1f}%)", flush=True)
    finally:
        os.close(fd)
    checksum = 0
    with partial.open("rb") as source:
        for data in iter(lambda: source.read(8 * 1024 * 1024), b""):
            checksum = zlib.crc32(data, checksum)
    if checksum != meta["crc32"]:
        raise ValueError("CRC32 mismatch; keep the partial download for diagnosis")
    partial.replace(output)
    checkpoint.unlink()
    output.with_suffix(output.suffix + ".source.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"Verified CRC32 {checksum:08x}: {output}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("member")
    parser.add_argument("output", type=Path)
    parser.add_argument("--workers", type=int, default=16, choices=range(1, 33))
    args = parser.parse_args()
    download(args.url, args.member, args.output, args.workers)
