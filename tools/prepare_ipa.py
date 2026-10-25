#!/usr/bin/env python3
"""Stage an owned IPA and generate the auditable Gate 0 fixtures; no Apple files in Git."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "hamintosh/src/main/resources/rawfile"
CODE = bytes.fromhex("40058052c0035fd6")  # mov w0,#42; ret


def make_probe(code=CODE):
    entry = 0x1000
    size = entry + len(code)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 2, 96, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0x100000000,
                          0x4000, 0, size, 5, 5, 0, 0)
    main = struct.pack("<IIQQ", 0x80000028, 24, entry, 0)
    return (header + segment + main).ljust(entry, b"\0") + code


def stage(ipa: Path):
    target = RAW / "target"
    artifact = ROOT / "artifacts/imported"
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive entries")
        if sum(m.file_size for m in archive.infolist()) > 512 * 1024 * 1024:
            raise ValueError("IPA exceeds the 512 MiB staging limit")
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in member.filename or stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError(f"Unsafe IPA member: {member.filename}")
        infos = [n for n in names if n.startswith("Payload/") and n.count("/") == 2 and n.endswith(".app/Info.plist")]
        if len(infos) != 1:
            raise ValueError("Expected exactly one top-level .app/Info.plist")
        info = plistlib.loads(archive.read(infos[0]))
        executable = info["CFBundleExecutable"]
        if not isinstance(executable, str) or not executable or PurePosixPath(executable).name != executable:
            raise ValueError("Invalid CFBundleExecutable")
        bundle = infos[0].rsplit("/", 1)[0]
        binary = archive.read(f"{bundle}/{executable}")
        # Extract only the selected bundle into a private, ignored local staging area.
        destination = artifact / PurePosixPath(bundle).name
        if destination.exists():
            shutil.rmtree(destination)
        for member in archive.infolist():
            if not member.filename.startswith(bundle + "/") or member.is_dir():
                continue
            rel = PurePosixPath(member.filename).relative_to(bundle)
            out = destination.joinpath(*rel.parts)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(archive.read(member))
    target.mkdir(parents=True, exist_ok=True)
    packaged_bundle = target / "bundle"
    if packaged_bundle.exists():
        shutil.rmtree(packaged_bundle)
    shutil.copytree(destination, packaged_bundle)
    bundle_files = sorted(str(path.relative_to(packaged_bundle)) for path in packaged_bundle.rglob('*') if path.is_file())
    (target / "executable").write_bytes(binary)
    manifest = {
        "name": info.get("CFBundleDisplayName", info.get("CFBundleName", executable)),
        "bundleId": info["CFBundleIdentifier"], "executable": executable,
        "minimumOS": info.get("MinimumOSVersion", "unknown"),
        "sdk": info.get("DTSDKName", "unknown"),
        "sha256": hashlib.sha256(binary).hexdigest(), "sourceIPA": str(ipa.resolve()),
        "bundleDirectory": destination.name, "bundleFiles": bundle_files,
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
    print(f"Staged bundle: {destination}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path, nargs="?")
    args = parser.parse_args()
    probes = RAW / "probes"
    probes.mkdir(parents=True, exist_ok=True)
    (probes / "execution_probe.bin").write_bytes(CODE)
    (probes / "return42.macho").write_bytes(make_probe())
    fixtures = ROOT / "tests/fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    (fixtures / "return42.macho").write_bytes(make_probe())
    if args.ipa:
        stage(args.ipa)


if __name__ == "__main__":
    main()
