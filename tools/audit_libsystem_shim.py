#!/usr/bin/env python3
"""Audit the AOT Darwin syscall boundary and emit libsystem-shim.json.

This tool deliberately distinguishes two properties:

* no selected Darwin ``svc #0x80`` or TPIDRRO read may reach the OHOS kernel;
* the Apple ``libsystem_kernel.dylib`` image has not yet been replaced at the
  symbol level, so its wrapper code still executes before the Harmintosh trap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SVC80 = 0xD4001001
TPIDRRO_MASK = ~31 & 0xFFFFFFFF
TPIDRRO = 0xD53BD060
TRAP_MARKER = 0xD42909A0
TPIDRRO_TRAP_MASK = ~0x3ff & 0xFFFFFFFF
TPIDRRO_TRAP = 0xD4294000


def words(data):
    if len(data) % 4:
        raise ValueError("Instruction bytes are not word aligned")
    return (struct.unpack_from("<I", data, at)[0] for at in range(0, len(data), 4))


def count_darwin_calls(data):
    svc = tpidrro = 0
    for word in words(data):
        svc += word == SVC80
        tpidrro += word & TPIDRRO_MASK == TPIDRRO
    return {"svc80": svc, "tpidrro": tpidrro}


def count_traps(data):
    svc = tpidrro = 0
    for word in words(data):
        svc += word == TRAP_MARKER
        tpidrro += word & TPIDRRO_TRAP_MASK == TPIDRRO_TRAP
    return {"svc80": svc, "tpidrro": tpidrro}


def _read_range(record):
    with Path(record["path"]).open("rb") as source:
        source.seek(record["fileOffset"])
        data = source.read(record["size"])
    if len(data) != record["size"]:
        raise ValueError("Truncated selected cache range")
    return data


def audit_ranges(ranges, patches, output):
    output = Path(output)
    source_totals = {"svc80": 0, "tpidrro": 0}
    packed_totals = {"svc80": 0, "tpidrro": 0}
    patch_totals = {"svc80": 0, "tpidrro": 0}
    marked_totals = {"svc80": 0, "tpidrro": 0}
    issues = []
    selected = 0
    for index, record in enumerate(ranges):
        if not record["protection"] & 4:
            continue
        selected += 1
        source = _read_range(record)
        piece = output / f"pages-{index:03}.bin"
        if not piece.is_file():
            issues.append(f"missing executable piece {piece.name}")
            continue
        packed = piece.read_bytes()
        if len(packed) != record["size"]:
            issues.append(f"packed size mismatch for {piece.name}")
            continue
        source_counts = count_darwin_calls(source)
        packed_counts = count_darwin_calls(packed)
        marked_counts = count_traps(packed)
        low, high = record["offset"], record["offset"] + record["size"]
        range_patches = [item for item in patches if low <= item["offset"] < high]
        patch_counts = {
            "svc80": sum(item.get("original") == "svc #0x80" for item in range_patches),
            "tpidrro": sum(str(item.get("original", "")).startswith("mrs ") for item in range_patches),
        }
        for key in source_totals:
            source_totals[key] += source_counts[key]
            packed_totals[key] += packed_counts[key]
            marked_totals[key] += marked_counts[key]
            patch_totals[key] += patch_counts[key]
        for key in source_totals:
            if source_counts[key] != patch_counts[key]:
                issues.append(f"{piece.name}: {key} source/patch mismatch {source_counts[key]}/{patch_counts[key]}")
            if marked_counts[key] != patch_counts[key]:
                issues.append(f"{piece.name}: {key} trap/patch mismatch {marked_counts[key]}/{patch_counts[key]}")
        if packed_counts["svc80"] or packed_counts["tpidrro"]:
            issues.append(
                f"{piece.name}: remaining svc80={packed_counts['svc80']} "
                f"tpidrro={packed_counts['tpidrro']}"
            )
    # The package can contain executable source bytes that were not written to
    # pieces when a range was superseded during selection. Count patch records
    # independently and compare them with the source totals.
    return {
        "selectedExecutableRanges": selected,
        "source": source_totals,
        "patched": patch_totals,
        "packedRemaining": packed_totals,
        "trapMarkers": marked_totals,
        "issues": issues,
    }


def _uleb(data, at):
    value = 0
    for shift in range(0, 64, 7):
        if at >= len(data):
            raise ValueError("Truncated ULEB128")
        byte = data[at]
        at += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, at
    raise ValueError("ULEB128 overflow")


def parse_export_trie(data, image_address):
    """Return direct exports as ``{name, address}`` from a Mach-O trie."""
    pending = [(0, "")]
    visited = set()
    exports = []
    while pending:
        node, prefix = pending.pop()
        if node in visited or len(prefix) > 4096:
            raise ValueError("Cyclic or excessive export trie")
        visited.add(node)
        terminal_size, cursor = _uleb(data, node)
        terminal_end = cursor + terminal_size
        if terminal_end > len(data):
            raise ValueError("Export terminal escapes trie")
        if terminal_size:
            flags, payload = _uleb(data, cursor)
            if flags & ~0x1f:
                raise ValueError("Unsupported export flags")
            if not flags & 0x08:  # Reexports have no address payload.
                offset, payload = _uleb(data, payload)
                if flags & 0x10:  # Stub-and-resolver exports contain two offsets.
                    _, payload = _uleb(data, payload)
                if payload > terminal_end:
                    raise ValueError("Export payload escapes terminal")
                exports.append({"name": prefix, "address": image_address + offset})
        cursor = terminal_end
        if cursor >= len(data):
            raise ValueError("Truncated export edge count")
        count = data[cursor]
        cursor += 1
        for _ in range(count):
            end = data.find(b"\0", cursor)
            if end < 0:
                raise ValueError("Unterminated export edge")
            edge = data[cursor:end].decode("utf-8")
            child, cursor = _uleb(data, end + 1)
            pending.append((child, prefix + edge))
    return sorted(exports, key=lambda item: (item["address"], item["name"]))


def _package_image(package, suffix):
    for image in package.get("demandImages", []):
        if image.get("path", "").endswith(suffix):
            return image
    return None


def build_manifest(package, cache, boundary):
    status = "svc-boundary-verified-wrapper-still-executed" if not boundary["issues"] else "invalid"
    kernel = _package_image(package, "/libsystem_kernel.dylib")
    exports = []
    if kernel:
        try:
            from pack_cache import image_segments, read_vm
            segments, _ = image_segments(cache, kernel["address"], 6)
            export_segment = next((segment for segment in segments if "exportsAddress" in segment), None)
            if export_segment:
                exports = parse_export_trie(
                    read_vm(cache, export_segment["exportsAddress"], export_segment["exportsSize"]),
                    kernel["address"],
                )
        except (OSError, ValueError) as error:
            boundary["issues"].append(f"libsystem_kernel export trie: {error}")
            status = "invalid"
    return {
        "schemaVersion": 1,
        "status": status,
        "replacementLevel": "svc-trap-boundary",
        "directHostSyscallABI": False,
        "fullLibsystemKernelReplacement": False,
        "appleWrapperImagesExecuted": [kernel["path"]] if kernel else [],
        "boundary": boundary,
        "libsystemKernel": {
            "path": kernel["path"] if kernel else None,
            "exportCount": len(exports),
            "exportNamesSha256": hashlib.sha256(
                "\n".join(item["name"] for item in exports).encode()
            ).hexdigest(),
            "exports": exports,
            "disposition": "apple-wrapper-trampolined" if exports else "unavailable",
        },
        "remainingHardBlocker": (
            "Bind selected libsystem_kernel exports directly to Harmintosh-owned implementations "
            "before claiming full libsystem_kernel replacement."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("primary", type=Path)
    parser.add_argument("cache_info", type=Path)
    parser.add_argument("package", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    cache = json.loads(args.cache_info.read_text())
    package = json.loads(args.package.read_text())
    boundary = audit_ranges(package["ranges"], package.get("syscallPatches", []), args.output)
    manifest = build_manifest(package, cache, boundary)
    report = args.output / "libsystem-shim.json"
    report.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({key: manifest[key] for key in (
        "status", "replacementLevel", "directHostSyscallABI",
        "fullLibsystemKernelReplacement", "remainingHardBlocker"
    )}, indent=2))
    print(f"libsystem shim audit: {report}")
    if manifest["status"] != "svc-boundary-verified-wrapper-still-executed":
        raise SystemExit("Darwin syscall boundary audit failed: " + "; ".join(boundary["issues"]))


if __name__ == "__main__":
    main()
