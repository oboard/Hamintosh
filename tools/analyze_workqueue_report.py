#!/usr/bin/env python3
"""Decode bounded guest workloop change lists from a device report."""

import argparse
import json
from pathlib import Path
import re
import struct


def analyze(report):
    message = report.get('dyldBootstrap', {}).get('message', '')
    pattern = r'\[scene=([01]) wl=0x([0-9a-f]+) flags=0x([0-9a-f]+) words=((?: 0x[0-9a-f]+){9})\]'
    events = []
    for match in re.finditer(pattern, message):
        raw = b''.join(int(word, 16).to_bytes(8, 'little')
                       for word in match[4].split())
        ident, filter_, flags, qos, udata, fflags, xflags, data, *ext = struct.unpack(
            '<QhHIQIIq4Q', raw)
        events.append({
            'scene': bool(int(match[1])), 'workloop': hex(int(match[2], 16)),
            'syscallFlags': hex(int(match[3], 16)), 'ident': hex(ident),
            'filter': filter_, 'flags': hex(flags), 'qos': hex(qos),
            'udata': hex(udata), 'fflags': hex(fflags), 'xflags': hex(xflags),
            'data': data, 'ext': [hex(value) for value in ext],
            'threadRequest': filter_ == -17 and bool(fflags & 1),
        })
    dropped = re.search(r'guest kevent changes dropped=(\d+)', message)
    return {'events': events, 'dropped': int(dropped[1]) if dropped else None,
            'threadRequests': sum(event['threadRequest'] for event in events)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(json.loads(args.report.read_text())), indent=2))


if __name__ == '__main__':
    main()
