#!/usr/bin/env python3
"""Download one stored IPSW member with resumable aria2 connections.

A loopback range projection exposes just the member, so aria2 never downloads
the surrounding multi-GB IPSW. aria2 owns piece scheduling and its resume file.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
import urllib.request
import zlib
from fetch_zip_member import locate


def download(url, member, output, connections=16):
    aria2 = shutil.which('aria2c')
    if not aria2:
        raise ValueError('aria2c is required')
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    source = locate(url, member, allow_deflate=True)
    transfer_size = source.get('compressedSize', source['size'])
    deflated = source.get('method', 0) == 8
    partial = output.with_suffix(output.suffix + ('.compressed.partial' if deflated else '.partial'))
    state = output.with_suffix(output.suffix + '.aria2-source.json')
    final_source = output.with_suffix(output.suffix + '.source.json')
    if output.exists():
        if not final_source.exists() or json.loads(final_source.read_text()) != source:
            raise ValueError('Existing output has no matching verified source metadata')
        target = output
    else:
        if partial.exists() and (not state.exists() or json.loads(state.read_text()) != source):
            raise ValueError('Partial download has no matching aria2 source metadata')
        state.write_text(json.dumps(source, indent=2) + '\n')

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def serve(self, head=False):
                if self.path != '/member':
                    self.send_error(404)
                    return
                start, end = 0, transfer_size - 1
                ranged = self.headers.get('Range')
                if ranged:
                    match = re.fullmatch(r'bytes=(\d+)-(\d*)', ranged)
                    if not match:
                        self.send_error(416)
                        return
                    start = int(match[1])
                    end = min(int(match[2]), end) if match[2] else end
                    if start > end:
                        self.send_error(416)
                        return
                upstream = None
                try:
                    if not head:
                        begin, finish = source['start'] + start, source['start'] + end
                        request = urllib.request.Request(url, headers={
                            'Range': f'bytes={begin}-{finish}', 'Accept-Encoding': 'identity'})
                        upstream = urllib.request.urlopen(request, timeout=45)
                        if upstream.status != 206 or not upstream.headers.get('Content-Range', '').startswith(f'bytes {begin}-{finish}/'):
                            raise ValueError('Upstream did not honor member range')
                        if source['etag'] and upstream.headers.get('ETag') != source['etag']:
                            raise ValueError('Upstream archive identity changed')
                    self.send_response(206 if ranged else 200)
                    self.send_header('Content-Length', str(end - start + 1))
                    self.send_header('Accept-Ranges', 'bytes')
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('ETag', source['etag'])
                    if ranged:
                        self.send_header('Content-Range', f'bytes {start}-{end}/{transfer_size}')
                    self.end_headers()
                    if head:
                        return
                    left = end - start + 1
                    while left:
                        data = upstream.read(min(left, 128 * 1024))
                        if not data:
                            break
                        self.wfile.write(data)
                        left -= len(data)
                    if left:
                        self.close_connection = True
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except Exception:
                    # Closing a failed response lets aria2 resume this exact piece.
                    self.close_connection = True
                finally:
                    if upstream:
                        upstream.close()

            def do_HEAD(self):
                self.serve(True)

            def do_GET(self):
                self.serve()

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        print(f'aria2: {member}, transfer {transfer_size} bytes, up to {connections} connections', flush=True)
        try:
            subprocess.run([aria2, '--continue=true', f'--max-connection-per-server={connections}',
                f'--split={connections}', '--min-split-size=1M', '--file-allocation=none',
                '--auto-file-renaming=false', '--allow-overwrite=false', '--retry-wait=2',
                '--max-tries=20', '--timeout=60', '--connect-timeout=10', '--disk-cache=32M',
                '--enable-color=false', '--summary-interval=10', '--show-console-readout=false',
                '--no-proxy=127.0.0.1,localhost', f'--dir={partial.parent}', f'--out={partial.name}',
                f'http://127.0.0.1:{server.server_port}/member'], check=True)
        finally:
            server.shutdown()
            server.server_close()
        if partial.stat().st_size != transfer_size:
            raise ValueError('Downloaded compressed member length mismatch')
        target = partial
        if deflated:
            target = output.with_suffix(output.suffix + '.inflating')
            decoder = zlib.decompressobj(-15)
            produced = 0
            with partial.open('rb') as compressed, target.open('wb') as expanded:
                for chunk in iter(lambda: compressed.read(1024 * 1024), b''):
                    while chunk:
                        data = decoder.decompress(chunk, 8 * 1024 * 1024)
                        produced += len(data)
                        if produced > source['size']:
                            raise ValueError('ZIP member expands beyond declared size')
                        expanded.write(data)
                        chunk = decoder.unconsumed_tail
            if not decoder.eof or decoder.unused_data:
                raise ValueError('Invalid ZIP deflate stream')
    if target.stat().st_size != source['size']:
        raise ValueError('Downloaded member length mismatch')
    checksum = 0
    with target.open('rb') as stream:
        for data in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            checksum = zlib.crc32(data, checksum)
    if checksum != source['crc32']:
        raise ValueError('Downloaded member CRC32 mismatch')
    if target != output:
        target.replace(output)
    if deflated:
        partial.unlink(missing_ok=True)
    final_source.write_text(json.dumps(source, indent=2) + '\n')
    state.unlink(missing_ok=True)
    print(f'Verified CRC32 {checksum:08x}: {output}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('member')
    parser.add_argument('output', type=Path)
    parser.add_argument('--connections', type=int, default=16, choices=range(1, 17))
    args = parser.parse_args()
    download(args.url, args.member, args.output, args.connections)
