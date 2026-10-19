#!/usr/bin/env python3
"""Manage ProxyForge snapshots, Transfer.sh uploads, and README links."""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / os.getenv('OUTPUT_DIR', 'proxy-lists')
BASE = os.getenv('TRANSFER_BASE', '').rstrip('/')
KINDS = ('http', 'https', 'socks4', 'socks5')
START_MARK = '<!-- PROXYFORGE-LINKS-START -->'
END_MARK = '<!-- PROXYFORGE-LINKS-END -->'
LINKS = ROOT / '.github' / 'proxyforge_links.json'
INTERVAL = int(os.getenv('UPLOAD_SECONDS', '600'))
DURATION = int(os.getenv('CYCLE_SECONDS', '2580'))

def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, **kwargs)

def snapshot():
    """Copy growing outputs to stable temporary files, without blocking checker."""
    OUT.mkdir(exist_ok=True, parents=True)
    found = []
    for kind in KINDS:
        source = OUT / f'{kind}_proxies.txt'
        if source.is_file() and source.stat().st_size:
            dest = OUT / f'.{kind}.snapshot.txt'
            with source.open('rb') as reader, dest.open('wb') as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
            if dest.stat().st_size:
                found.append((kind, dest))
    return found

def upload(kind, path):
    # Transfer.sh native upload is PUT /filename and returns a generated URL.
    result = run(['curl', '--fail-with-body', '--silent', '--show-error',
                  '--retry', '2', '--retry-delay', '3', '--connect-timeout', '12',
                  '--max-time', '90', '--upload-file', str(path),
                  f'{BASE}/{kind}_proxies.txt'], capture_output=True, text=True)
    if result.returncode:
        print(f'[upload] {kind}: {result.stderr.strip()}', flush=True)
        return None
    url = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ''
    parsed = urlparse(url)
    if parsed.scheme != 'https' or parsed.netloc != urlparse(BASE).netloc or not parsed.path:
        print(f'[upload] {kind}: unexpected response: {result.stdout[:250]!r}', flush=True)
        return None
    return url

def render_readme(links):
    readme = ROOT / 'README.md'
    current = readme.read_text(encoding='utf-8') if readme.exists() else '# ProxyForge\n'
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    lines = ['## Latest temporary downloads', '', f'Updated: {now}', '',
             '| Protocol | Transfer.sh link |', '|---|---|']
    for kind in KINDS:
        url = links.get(kind, '')
        lines.append(f'| {kind.upper()} | [Download]({url}) |' if url else f'| {kind.upper()} | Not uploaded yet |')
    lines += ['', 'Links are temporary and may expire or become unavailable when the hosting runner restarts.']
    block = START_MARK + '\n' + '\n'.join(lines) + '\n' + END_MARK
    if START_MARK in current and END_MARK in current:
        current = re.sub(re.escape(START_MARK) + r'.*?' + re.escape(END_MARK),
                         lambda _: block, current, flags=re.S)
    else:
        current = current.rstrip() + '\n\n' + block + '\n'
    readme.write_text(current, encoding='utf-8')

def commit(paths, label):
    if not paths:
        return
    # Rebase only tracked metadata; do not pull unrelated changes into running scraper.
    run(['git', 'add', '--', *paths], check=True)
    if run(['git', 'diff', '--cached', '--quiet']).returncode == 0:
        return
    run(['git', 'commit', '-m', label], check=True)
    # Fetch/rebase allows previous pushes while this job has been running.
    for attempt in range(3):
        run(['git', 'fetch', 'origin', 'main'], check=True)
        result = run(['git', 'rebase', 'origin/main'], capture_output=True, text=True)
        if result.returncode:
            run(['git', 'rebase', '--abort'])
            raise RuntimeError(f'rebase failed: {result.stderr}')
        result = run(['git', 'push', 'origin', 'HEAD:main'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f'[git] {label}', flush=True)
            return
        print(f'[git] push retry {attempt + 1}: {result.stderr.strip()}', flush=True)
    raise RuntimeError('git push failed after retries')

def publish():
    if not BASE.startswith('https://'):
        print('[upload] TRANSFER_BASE not configured', flush=True)
        return
    links = json.loads(LINKS.read_text()) if LINKS.exists() else {}
    updated = False
    for kind, path in snapshot():
        url = upload(kind, path)
        if url:
            links[kind] = url
            updated = True
            print(f'[upload] {kind}: {url}', flush=True)
    if updated:
        LINKS.parent.mkdir(parents=True, exist_ok=True)
        LINKS.write_text(json.dumps(links, indent=2) + '\n')
        render_readme(links)
        commit(['README.md', '.github/proxyforge_links.json'], 'docs: refresh proxy download links [skip ci]')

def finalize():
    paths = [str(p.relative_to(ROOT)) for p in OUT.glob('*_proxies.txt') if p.is_file()]
    paths += [str(p.relative_to(ROOT)) for p in OUT.glob('*_proxies_inconclusive.txt') if p.is_file()]
    if paths:
        commit(paths, 'data: archive latest proxy lists [skip ci]')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--finalize-only', action='store_true')
    args = parser.parse_args()
    if args.finalize_only:
        finalize()
        return
    OUT.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, '-u', 'pfm_fixed.py', '--type', *KINDS,
           '--supersonic', '--output-dir', str(OUT),
           '--fetch-concurrency', '24', '--fast-window', '0.15',
           '--tunnel-timeout', '8', '--source-timeout', '8',
           '--max-candidates', '250000']
    print('[checker] ' + ' '.join(cmd), flush=True)
    checker = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL,
                               stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + DURATION
    next_upload = time.monotonic() + INTERVAL
    try:
        while time.monotonic() < deadline:
            if checker.poll() is not None:
                print(f'[checker] exited with code {checker.returncode}', flush=True)
                break
            wait = min(5, max(0, next_upload - time.monotonic()),
                       max(0, deadline - time.monotonic()))
            if wait:
                time.sleep(wait)
            if time.monotonic() >= next_upload:
                try:
                    publish()
                except Exception as exc:
                    print(f'[publish] {exc}', flush=True)
                next_upload = time.monotonic() + INTERVAL
    finally:
        if checker.poll() is None:
            os.killpg(checker.pid, signal.SIGTERM)
            try:
                checker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(checker.pid, signal.SIGKILL)
                checker.wait()
        try:
            publish()
        except Exception as exc:
            print(f'[publish final] {exc}', flush=True)
        finalize()

if __name__ == '__main__':
    main()
