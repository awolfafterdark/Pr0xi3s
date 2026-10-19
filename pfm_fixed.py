#!/usr/bin/env python3

"""ProxyForge Mobile 1.4.0: portable scraper/checker. Python 3.11+, no dependencies.
CLI: python proxyforge_mobile.py --type socks5  # all collected; saves proxies.txt
Multiple types: --type http socks5  # TYPE_proxies.txt per type
Sync API: get_proxies("socks5")  # count=0 (all collected)
Async API: await get_proxies_async("socks5", count=20)
Generated from the shared ProxyForge modules; rebuild with tools/build_mobile.py.
MIT code; source/feed attribution and update evidence are in the combined package.
"""

from __future__ import annotations


# ---- Shared module: models ----

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit
PROTOCOLS = ('http', 'https', 'socks4', 'socks5')

@dataclass(frozen=True, slots=True)
class Proxy:
    protocol: str
    host: str
    port: int
    username: str = field(default='', repr=False)
    password: str = field(default='', repr=False)

    @property
    def endpoint(self) -> str:
        host = f'[{self.host}]' if ':' in self.host else self.host
        return f'{host}:{self.port}'

    def uri(self, credentials: bool=False) -> str:
        auth = ''
        if self.username or self.password:
            auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@" if credentials else 'REDACTED@'
        return f'{self.protocol}://{auth}{self.endpoint}'

def parse_proxy(value: str, hint: str='http', allow_private: bool=False) -> Proxy | None:
    """Accept literal IPv4/[IPv6], URI, or IPv4:port:user:password.

    A source's `https` hint denotes HTTP CONNECT capability; an explicit
    https:// URI denotes TLS to the proxy itself. Bare auto inputs use HTTP
    here; the extraction module expands auto candidates across three protocols.
    """
    value = value.strip().strip('"\'')
    if not value or any((ord(c) < 32 or c.isspace() for c in value)):
        return None
    explicit = '://' in value
    if not explicit:
        parts = value.split(':', 3)
        if len(parts) == 4 and parts[1].isdigit() and (parts[0].count('.') == 3):
            host, port, user, password = parts
            value = f"{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}"
        proto = 'http' if hint in ('auto', 'https') else hint
        value = f'{proto}://{value}'
    try:
        u = urlsplit(value)
        proto = {'socks5h': 'socks5', 'socks4a': 'socks4'}.get(u.scheme.lower(), u.scheme.lower())
        if proto not in PROTOCOLS or u.path not in ('', '/') or u.query or u.fragment:
            return None
        ip = ipaddress.ip_address(u.hostname or '')
        if '%' in str(ip) or (not allow_private and (not ip.is_global)):
            return None
        if not u.port or not 1 <= u.port <= 65535:
            return None
        user, password = (unquote(u.username or ''), unquote(u.password or ''))
        if any((ord(c) < 32 for c in user + password)):
            return None
        return Proxy(proto, str(ip), u.port, user, password)
    except (ValueError, TypeError):
        return None


# ---- Shared module: web_sources ----

import base64
import binascii
import ipaddress
import json
import re
from html.parser import HTMLParser

def decode_field(value):
    try:
        return base64.b64decode(value, validate=True).decode('ascii')
    except (ValueError, UnicodeError, binascii.Error):
        return ''

class PublicListHTML(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows, self.row, self.cell = ([], [], None)
        self.decoy = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'tr':
            self.row = []
            self.decoy = 'pv-decoy' in attrs.get('class', '').split()
        if tag in ('td', 'th'):
            self.cell = []
        if self.cell is not None:
            for key in ('data-ip', 'data-port'):
                if attrs.get(key):
                    self.cell.append(decode_field(attrs[key]))
            if attrs.get('data-text'):
                self.cell.append(attrs['data-text'])
            if attrs.get('data-p'):
                self.cell.append(decode_field(attrs['data-p'])[::-1])

    def handle_data(self, data):
        if self.cell is not None:
            encoded = re.search('Base64\\.decode\\(["\']([A-Za-z0-9+/=]+)["\']\\)', data)
            self.cell.append(decode_field(encoded[1]) if encoded else data)

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None:
            self.row.append(' '.join(self.cell).strip())
            self.cell = None
        elif tag == 'tr' and self.row and (not self.decoy):
            self.rows.append(self.row)

def web_pairs(text, hint):
    """Match row-local IP/port and protocol; support public display encodings."""
    parser = PublicListHTML()
    parser.feed(text)
    for row in parser.rows:
        endpoint = None
        for index, cell in enumerate(row):
            match = re.search('(?<![\\d.])((?:\\d{1,3}\\.){3}\\d{1,3})(?::(\\d{1,5}))?', cell)
            if not match:
                continue
            try:
                ipaddress.ip_address(match[1])
            except ValueError:
                continue
            port = match[2]
            if not port and index + 1 < len(row):
                p = re.fullmatch('\\s*(\\d{1,5})\\s*', row[index + 1])
                port = p[1] if p else None
            if port:
                endpoint = f'{match[1]}:{port}'
                break
        if endpoint:
            protocols = re.findall('https?|socks\\s*[45]', ' '.join(row).lower())
            for protocol in dict.fromkeys((p.replace(' ', '') for p in protocols)):
                yield (endpoint, 'http' if protocol == 'https' else protocol)
            if not protocols:
                yield (endpoint, hint)
    for encoded in re.findall('\\bProxy\\(["\']([A-Za-z0-9+/=]+)["\']\\)', text):
        yield (decode_field(encoded), hint)
    match = re.search('\\bfpsList\\s*=\\s*(\\[[\\s\\S]*?\\])\\s*;', text)
    if match:
        try:
            rows = json.loads(match[1])
        except (ValueError, RecursionError):
            return
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and row.get('ip') and row.get('port'):
                    for protocol in re.findall('https?|socks[45]', str(row.get('protocol', hint)).lower()):
                        yield (f"{row['ip']}:{row['port']}", 'http' if protocol == 'https' else protocol)


# ---- Shared module: extract ----

import csv
import io
import json
import re
from dataclasses import replace
from urllib.parse import quote
from html.parser import HTMLParser
from collections.abc import Iterator
TOKEN = re.compile('(?<![\\w.:])(?:(?:https?|socks4a?|socks5h?)://)?(?:[^\\s<>\\"\'@/]+@)?(?:\\[[0-9a-fA-F:]+\\]|\\d{1,3}(?:\\.\\d{1,3}){3}):\\d{1,5}(?!\\d)(?::[^\\s<>\\"\']+)?', re.I)

class TableParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[list[str]] = []
        self.row: list[str] = []
        self.cell: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self.row = []
        elif tag in ('td', 'th'):
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None:
            self.row.append(''.join(self.cell).strip())
            self.cell = None
        elif tag == 'tr' and self.row:
            self.rows.append(self.row)

def _objects(obj, hint: str, depth: int=0) -> Iterator[tuple[str, str]]:
    if depth > 24:
        return
    if isinstance(obj, str):
        yield (obj, hint)
    elif isinstance(obj, list):
        for item in obj:
            yield from _objects(item, hint, depth + 1)
    elif isinstance(obj, dict):
        d = {str(k).lower(): v for k, v in obj.items()}
        protocols = d.get('protocols', d.get('protocol', d.get('type', hint)))
        if not isinstance(protocols, list):
            protocols = re.findall('https?|socks[45]|auto', str(protocols).lower())
        protocols = [str(p).lower() for p in protocols if str(p).lower() in ('http', 'https', 'socks4', 'socks5', 'auto')]
        if not protocols and ('protocol' in d or 'protocols' in d) and (d.get('ip') or d.get('host') or d.get('addr') or d.get('ip_address')):
            return
        protocols = protocols or [hint]
        host = d.get('ip', d.get('host', d.get('ipaddress', d.get('ip_address', d.get('addr')))))
        port = d.get('port')
        if host and port:
            host = str(host)
            endpoint = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            user, password = (d.get('username', ''), d.get('password', ''))
            if user or password:
                endpoint = f"{quote(str(user), safe='')}:{quote(str(password), safe='')}@{endpoint}"
            for p in protocols:
                yield (endpoint, p)
        else:
            for k, value in d.items():
                next_hint = k if k in ('http', 'https', 'socks4', 'socks5') else protocols[0]
                yield from _objects(value, next_hint, depth + 1)

def extract(text: str, hint: str='auto', fmt: str='auto', *, allow_private: bool=False, limit: int=100000, proxy_type: str='all') -> list[Proxy]:
    """Parse text, JSON, CSV, or HTML without executing page code."""
    if limit < 1:
        return []
    stripped = text.lstrip('\ufeff \n\r\t')
    if fmt == 'auto' and stripped:
        first = stripped.splitlines()[0].lower()
        columns = {c.strip().strip('"') for c in first.split(',')}
        if 'port' in columns and columns.intersection({'ip', 'host', 'ipaddress'}):
            fmt = 'csv'
    values: Iterator[tuple[str, str]]
    if fmt == 'web_html':
        values = web_pairs(text, hint)
    elif fmt == 'json' or (fmt == 'auto' and stripped.startswith(('{', '[')) and (not re.match('\\[[\\da-fA-F:]+\\]:', stripped))):
        try:
            values = _objects(json.loads(stripped), hint)
        except (ValueError, RecursionError):
            return []
    elif fmt == 'html' or (fmt == 'auto' and '<table' in text.lower()):
        parser = TableParser()
        parser.feed(text)
        values = ((f'{row[0]}:{row[1]}', hint) for row in parser.rows if len(row) >= 2)
    elif fmt == 'csv_rows':
        values = ((f'{row[0].strip()}:{row[1].strip()}', hint) for row in csv.reader(io.StringIO(text)) if len(row) >= 2)
    elif fmt == 'csv':
        values = (pair for row in csv.DictReader(io.StringIO(text)) for pair in _objects(row, hint))
    else:
        values = ((line.strip(), hint) for line in text.splitlines() if line.strip() and (not line.lstrip().startswith(('#', ';', '//'))))
    found: dict[Proxy, None] = {}
    for value, protocol in values:
        candidates = [value]
        if not parse_proxy(value, protocol, allow_private):
            if '://' in value and (not value.lower().startswith(('http://', 'https://', 'socks4://', 'socks4a://', 'socks5://', 'socks5h://'))):
                continue
            candidates = TOKEN.findall(value)
        for token in candidates:
            proxy = parse_proxy(token, protocol, allow_private)
            if proxy is None:
                continue
            expanded = [proxy]
            if protocol == 'auto' and '://' not in token:
                expanded = [replace(proxy, protocol=p) for p in ('http', 'socks4', 'socks5')]
            for p in expanded:
                if not candidate_matches(p, proxy_type):
                    continue
                found[p] = None
                if len(found) >= limit:
                    return list(found)
    return list(found)


# ---- Shared module: transport ----

import asyncio
import base64
import ipaddress
import json
import ssl
import struct
import time
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
MAX_HEADERS = 32768
MAX_BODY = 131072

class ProbeError(Exception):
    pass

async def read_headers(reader: asyncio.StreamReader) -> tuple[int, dict[str, str]]:
    try:
        block = await reader.readuntil(b'\r\n\r\n')
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError) as exc:
        raise ProbeError('invalid_http_headers') from exc
    return decode_headers(block)

def decode_headers(block: bytes) -> tuple[int, dict[str, str]]:
    """Validate one bounded header block for both stream and callback transports."""
    if len(block) > MAX_HEADERS:
        raise ProbeError('headers_too_large')
    lines = block.decode('iso-8859-1').split('\r\n')
    status = lines[0].split(' ', 2)
    if len(status) < 2 or status[0] not in ('HTTP/1.0', 'HTTP/1.1') or (not status[1].isdigit()):
        raise ProbeError('invalid_http_status')
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ':' not in line:
            raise ProbeError('invalid_http_header')
        name, value = line.split(':', 1)
        name = name.strip().lower()
        if name in headers:
            if name in ('content-length', 'transfer-encoding'):
                raise ProbeError('ambiguous_framing')
            headers[name] += ',' + value.strip()
        else:
            headers[name] = value.strip()
    return (int(status[1]), headers)

async def read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    if headers.get('content-encoding', 'identity').lower() not in ('', 'identity'):
        raise ProbeError('unexpected_content_encoding')
    if 'transfer-encoding' in headers and 'content-length' in headers:
        raise ProbeError('ambiguous_framing')
    if 'transfer-encoding' in headers:
        if headers['transfer-encoding'].lower() != 'chunked':
            raise ProbeError('unsupported_transfer_encoding')
        chunks = bytearray()
        count = 0
        while True:
            line = await reader.readline()
            if not line or len(line) > 256:
                raise ProbeError('invalid_chunk')
            try:
                size = int(line.split(b';', 1)[0].strip(), 16)
            except ValueError as exc:
                raise ProbeError('invalid_chunk') from exc
            if size < 0 or len(chunks) + size > MAX_BODY:
                raise ProbeError('body_too_large')
            if not size:
                trailer_bytes = 0
                while True:
                    trailer = await reader.readline()
                    trailer_bytes += len(trailer)
                    if trailer_bytes > MAX_HEADERS or not trailer:
                        raise ProbeError('invalid_trailers')
                    if trailer == b'\r\n':
                        return bytes(chunks)
            chunks.extend(await reader.readexactly(size))
            if await reader.readexactly(2) != b'\r\n':
                raise ProbeError('invalid_chunk')
            count += 1
            if count > 4096:
                raise ProbeError('too_many_chunks')
    if 'content-length' in headers:
        try:
            size = int(headers['content-length'])
        except ValueError as exc:
            raise ProbeError('invalid_content_length') from exc
        if not 0 <= size <= MAX_BODY:
            raise ProbeError('body_too_large')
        return await reader.readexactly(size)
    chunks = bytearray()
    while True:
        part = await reader.read(min(16384, MAX_BODY + 1 - len(chunks)))
        if not part:
            return bytes(chunks)
        chunks.extend(part)
        if len(chunks) > MAX_BODY:
            raise ProbeError('body_too_large')

def validate_judge(url: str, allow_http: bool=False) -> None:
    u = urlsplit(url)
    if u.scheme not in (('https', 'http') if allow_http else ('https',)) or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError('Judge must be an HTTPS echo URL without credentials or fragment; use --allow-http-judge explicitly for HTTP.')
    if any((ord(c) < 33 for c in url)):
        raise ValueError('Invalid judge URL')
    try:
        if u.port is not None and (not 1 <= u.port <= 65535):
            raise ValueError('Invalid judge port')
    except ValueError as exc:
        raise ValueError('Invalid judge port') from exc

def _authority(host: str, port: int) -> str:
    return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'

async def _tunnel(reader, writer, proxy: Proxy, host: str, port: int, use_tls: bool):
    target = _authority(host, port)
    if proxy.protocol in ('http', 'https'):
        if not use_tls:
            return
        auth = ''
        if proxy.username or proxy.password:
            raw = f'{proxy.username}:{proxy.password}'.encode()
            auth = 'Proxy-Authorization: Basic ' + base64.b64encode(raw).decode() + '\r\n'
        writer.write(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n'.encode())
        await writer.drain()
        status, _ = await read_headers(reader)
        interim = 0
        while 100 <= status < 200:
            interim += 1
            if interim > 4:
                raise ProbeError('too_many_interim_responses')
            status, _ = await read_headers(reader)
        if not 200 <= status < 300:
            raise ProbeError(f'connect_status_{status}')
    elif proxy.protocol == 'socks5':
        authenticated = bool(proxy.username or proxy.password)
        writer.write(b'\x05\x01' + (b'\x02' if authenticated else b'\x00'))
        await writer.drain()
        reply = await reader.readexactly(2)
        if reply != (b'\x05\x02' if authenticated else b'\x05\x00'):
            raise ProbeError('socks5_auth_method_rejected')
        if authenticated:
            user, password = (proxy.username.encode(), proxy.password.encode())
            if not 1 <= len(user) <= 255 or not 1 <= len(password) <= 255:
                raise ProbeError('socks5_auth_length')
            writer.write(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            await writer.drain()
            if await reader.readexactly(2) != b'\x01\x00':
                raise ProbeError('socks5_auth_failed')
        try:
            ip = ipaddress.ip_address(host)
            address = (b'\x01' if ip.version == 4 else b'\x04') + ip.packed
        except ValueError:
            domain = host.encode('idna')
            if not 1 <= len(domain) <= 255:
                raise ProbeError('target_hostname_too_long')
            address = b'\x03' + bytes([len(domain)]) + domain
        writer.write(b'\x05\x01\x00' + address + struct.pack('!H', port))
        await writer.drain()
        head = await reader.readexactly(4)
        if head[:3] != b'\x05\x00\x00':
            raise ProbeError(f'socks5_connect_rejected_{head[1]}')
        if head[3] == 1:
            await reader.readexactly(6)
        elif head[3] == 4:
            await reader.readexactly(18)
        elif head[3] == 3:
            length = (await reader.readexactly(1))[0]
            if not length:
                raise ProbeError('socks5_empty_bound_hostname')
            await reader.readexactly(length + 2)
        else:
            raise ProbeError('socks5_bad_address_type')
    elif proxy.protocol == 'socks4':
        if proxy.password:
            raise ProbeError('socks4_password_not_supported')
        user = proxy.username.encode()
        if b'\x00' in user or len(user) > 255:
            raise ProbeError('socks4_bad_userid')
        suffix = b''
        try:
            ip = ipaddress.ip_address(host)
            if ip.version != 4:
                raise ProbeError('socks4_ipv6_not_supported')
            address = ip.packed
        except ValueError:
            address = b'\x00\x00\x00\x01'
            suffix = host.encode('idna') + b'\x00'
        writer.write(b'\x04\x01' + struct.pack('!H', port) + address + user + b'\x00' + suffix)
        await writer.drain()
        reply = await reader.readexactly(8)
        if reply[:2] != b'\x00Z':
            raise ProbeError('socks4_connect_rejected')
    else:
        raise ProbeError('unsupported_proxy_protocol')

async def request_echo(url: str, proxy: Proxy | None=None, *, timeout: float=7, ssl_context: ssl.SSLContext | None=None) -> dict:
    """Fetch a nonce echo. Direct access is only used when proxy is None."""
    started = time.monotonic()
    nonce = uuid.uuid4().hex
    u = urlsplit(url)
    host = (u.hostname or '').encode('idna').decode()
    port = u.port or (443 if u.scheme == 'https' else 80)
    query = [(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True) if k != 'pf_nonce']
    query.append(('pf_nonce', nonce))
    target_path = urlunsplit(('', '', u.path or '/', urlencode(query), ''))
    absolute = urlunsplit((u.scheme, u.netloc, u.path or '/', urlencode(query), ''))
    writer = None
    ctx = ssl_context or ssl.create_default_context()
    try:
        async with asyncio.timeout(timeout):
            connect_host, connect_port = (proxy.host, proxy.port) if proxy else (host, port)
            initial_tls = proxy.protocol == 'https' if proxy else u.scheme == 'https'
            reader, writer = await asyncio.open_connection(connect_host, connect_port, ssl=ctx if initial_tls else None, server_hostname=connect_host if initial_tls else None, limit=MAX_HEADERS)
            if proxy:
                await _tunnel(reader, writer, proxy, host, port, u.scheme == 'https')
                if u.scheme == 'https':
                    await writer.start_tls(ctx, server_hostname=host, ssl_handshake_timeout=timeout)
            plain_http_proxy = proxy and proxy.protocol in ('http', 'https') and (u.scheme == 'http')
            path = absolute if plain_http_proxy else target_path
            auth = ''
            if plain_http_proxy and (proxy.username or proxy.password):
                raw = f'{proxy.username}:{proxy.password}'.encode()
                auth = 'Proxy-Authorization: Basic ' + base64.b64encode(raw).decode() + '\r\n'
            request = f'GET {path} HTTP/1.1\r\nHost: {_authority(host, port)}\r\nUser-Agent: ProxyForge/1.0\r\nX-Proxyforge-Nonce: {nonce}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n{auth}\r\n'
            writer.write(request.encode('ascii'))
            await writer.drain()
            status, headers = await read_headers(reader)
            if status != 200:
                raise ProbeError(f'judge_status_{status}')
            body = await read_body(reader, headers)
            try:
                data = json.loads(body)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ProbeError('judge_invalid_json') from exc
            if not isinstance(data, dict) or not isinstance(data.get('headers'), dict) or (not isinstance(data.get('args'), dict)):
                raise ProbeError('judge_missing_echo')
            echo_headers = {str(k).lower(): str(v) for k, v in data['headers'].items()}
            if echo_headers.get('x-proxyforge-nonce') != nonce or data['args'].get('pf_nonce') != nonce:
                raise ProbeError('nonce_mismatch')
            origin = data.get('origin') or data.get('ip')
            if not isinstance(origin, str):
                raise ProbeError('judge_missing_origin')
            try:
                ips = [str(ipaddress.ip_address(x.strip())) for x in origin.split(',')]
            except ValueError as exc:
                raise ProbeError('judge_invalid_origin') from exc
            return {'ok': True, 'latency_ms': round((time.monotonic() - started) * 1000, 2), 'exit_ips': ips, 'headers': echo_headers, 'tls': u.scheme == 'https', 'judge': url}
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if isinstance(exc, ProbeError):
            error = str(exc)
        elif isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
            error = 'timeout'
        elif isinstance(exc, ssl.SSLCertVerificationError):
            error = 'tls_certificate_rejected'
        else:
            error = type(exc).__name__
        return {'ok': False, 'error': error, 'judge': url, 'latency_ms': round((time.monotonic() - started) * 1000, 2)}
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.25)
            except (Exception, asyncio.CancelledError):
                if writer.transport:
                    writer.transport.abort()


# ---- Shared module: check ----

import asyncio
import hashlib
import json
import statistics
import ssl
import time
from pathlib import Path
DEFAULT_JUDGES = ('https://httpbin.org/get', 'https://postman-echo.com/get')

class RateLimiter:

    def __init__(self, rate: float):
        self.interval = 1 / rate if rate else 0
        self.next_time = 0.0
        self.lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self.lock:
            now = time.monotonic()
            await asyncio.sleep(max(0, self.next_time - now))
            self.next_time = time.monotonic() + self.interval

def anonymity(observations: list[dict], baseline_ips: set[str]) -> str:
    """An observation at the echo endpoint, never a privacy guarantee."""
    if not baseline_ips:
        return 'unknown'
    found_proxy_header = False
    for obs in observations:
        if baseline_ips.intersection(obs.get('exit_ips', [])):
            return 'transparent_observed'
        for key, value in obs.get('headers', {}).items():
            if key in ('forwarded', 'x-forwarded-for', 'client-ip', 'x-real-ip', 'via', 'proxy-connection'):
                found_proxy_header = True
                import re
                tokens = set(re.findall('[0-9a-fA-F:.]+', value))
                if baseline_ips.intersection(tokens):
                    return 'transparent_observed'
    return 'anonymous_observed' if found_proxy_header else 'no_proxy_headers_observed'

class Checker:

    def __init__(self, judges=DEFAULT_JUDGES, *, timeout=7.0, checks=2, quorum=2, rate=30.0, allow_http=False, require_egress_change=False, ssl_context=None):
        if checks < 1 or not 1 <= quorum <= checks:
            raise ValueError('Require 1 <= quorum <= checks')
        if not judges:
            raise ValueError('At least one judge is required')
        self.judges = list(dict.fromkeys(judges))
        for judge in self.judges:
            validate_judge(judge, allow_http)
        self.timeout, self.checks, self.quorum = (timeout, checks, quorum)
        self.require_egress_change = require_egress_change
        self.limiter = RateLimiter(rate)
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.baseline_ips: set[str] = set()
        self.preflight: list[dict] = []

    @property
    def fingerprint(self):
        data = [self.judges, self.timeout, self.checks, self.quorum, self.require_egress_change]
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()

    async def prepare(self):
        self.preflight = []
        for judge in self.judges:
            await self.limiter.wait()
            result = await request_echo(judge, timeout=self.timeout, ssl_context=self.ssl_context)
            self.preflight.append(result)
        healthy = [r for r in self.preflight if r['ok']]
        if not healthy:
            raise RuntimeError('No judge passed direct nonce/TLS preflight. Check connectivity or use --judge with your own echo endpoint.')
        self.judges = [r['judge'] for r in healthy]
        self.baseline_ips = {ip for r in healthy for ip in r['exit_ips']}

    async def check(self, proxy: Proxy) -> dict:
        observations = []
        successes = []
        for index in range(self.checks):
            await self.limiter.wait()
            obs = await request_echo(self.judges[index % len(self.judges)], proxy, timeout=self.timeout, ssl_context=self.ssl_context)
            if obs['ok'] and self.require_egress_change and self.baseline_ips.intersection(obs['exit_ips']):
                obs = dict(obs, ok=False, error='egress_unchanged')
            observations.append(obs)
            if obs['ok']:
                successes.append(obs)
            if len(successes) + self.checks - index - 1 < self.quorum:
                break
        latency = statistics.median((r['latency_ms'] for r in successes)) if successes else None
        ok = len(successes) >= self.quorum
        return {'proxy': proxy.uri(), 'protocol': proxy.protocol, 'endpoint': proxy.endpoint, 'ok': ok, 'successes': len(successes), 'attempts': len(observations), 'required_successes': self.quorum, 'latency_ms': latency, 'success_ratio': round(len(successes) / len(observations), 4), 'checked_at': time.time(), 'cached': False, 'tls_verified': bool(successes) and all((r['tls'] for r in successes)), 'exit_ips': sorted({ip for r in successes for ip in r['exit_ips']}), 'anonymity': anonymity(successes, self.baseline_ips) if successes else 'unknown', 'errors': [r['error'] for r in observations if not r['ok']], 'judges': [r['judge'] for r in observations], 'score': round(100 * len(successes) / len(observations) / (1 + (latency or 0) / 1000), 2) if ok else 0}


# ---- Shared module: selection ----

PROXY_TYPES = ('all', 'http', 'https', 'socks4', 'socks5')

def normalize_type(proxy_type: str) -> str:
    proxy_type = str(proxy_type).strip().lower()
    if proxy_type not in PROXY_TYPES:
        raise ValueError('proxy_type must be all, http, https, socks4, or socks5')
    return proxy_type

def source_matches(hint: str, proxy_type: str) -> bool:
    if proxy_type == 'all' or hint == 'auto':
        return True
    if proxy_type in ('http', 'https'):
        return hint in ('http', 'https')
    return hint == proxy_type

def candidate_matches(proxy, proxy_type: str) -> bool:
    if proxy_type == 'all':
        return True
    if proxy_type == 'https':
        return proxy.protocol in ('http', 'https')
    return proxy.protocol == proxy_type

def selected_hint(hint: str, proxy_type: str) -> str:
    if hint == 'auto' and proxy_type != 'all':
        return 'http' if proxy_type == 'https' else proxy_type
    return hint


# ---- Shared module: fast_transport ----

import asyncio
import ipaddress
import struct
from functools import lru_cache

@lru_cache(maxsize=64)
def tunnel_bytes(protocol, target):
    host, port = target
    if protocol == 'http':
        authority = _authority(host, port)
        return f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if protocol == 'socks4':
        if address and address.version != 4:
            raise ProbeError('socks4_ipv6_not_supported')
        packed = address.packed if address else b'\x00\x00\x00\x01'
        suffix = b'' if address else host.encode('idna') + b'\x00'
        return b'\x04\x01' + struct.pack('!H', port) + packed + b'\x00' + suffix
    if protocol == 'socks5':
        if address:
            packed = (b'\x01' if address.version == 4 else b'\x04') + address.packed
        else:
            name = host.encode('idna')
            if not 1 <= len(name) <= 255:
                raise ProbeError('target_hostname_too_long')
            packed = b'\x03' + bytes([len(name)]) + name
        return b'\x05\x01\x00' + packed + struct.pack('!H', port)
    raise ProbeError('unsupported_proxy_protocol')

class TunnelProtocol(asyncio.Protocol):
    """A small state machine: a future completes only on a full success reply."""

    def __init__(self, protocol, target, loop):
        self.kind = protocol
        self.request = tunnel_bytes(protocol, target)
        self.future = loop.create_future()
        self.transport = None
        self.buffer = bytearray()
        self.state = 'method' if protocol == 'socks5' else protocol
        self.interim = 0

    def connection_made(self, transport):
        self.transport = transport
        transport.write(b'\x05\x01\x00' if self.kind == 'socks5' else self.request)

    def connection_lost(self, exc):
        if not self.future.done():
            self.future.set_exception(exc or ProbeError('proxy_closed'))

    def _finish(self, error=None):
        if not self.future.done():
            if error:
                self.future.set_exception(error)
            else:
                self.future.set_result(None)
        self.buffer.clear()
        if self.transport:
            self.transport.pause_reading()

    def data_received(self, data):
        if self.future.done():
            return
        cap = MAX_HEADERS + 1 if self.kind == 'http' else 512
        self.buffer.extend(data[:max(0, cap - len(self.buffer))])
        try:
            while True:
                if self.state == 'http':
                    end = self.buffer.find(b'\r\n\r\n')
                    if end < 0:
                        if len(self.buffer) >= cap:
                            raise ProbeError('headers_too_large')
                        return
                    status, _ = decode_headers(bytes(self.buffer[:end + 4]))
                    del self.buffer[:end + 4]
                    if 100 <= status < 200:
                        self.interim += 1
                        if self.interim > 4:
                            raise ProbeError('too_many_interim_responses')
                        continue
                    if not 200 <= status < 300:
                        raise ProbeError(f'connect_status_{status}')
                    self._finish()
                    return
                if self.state == 'socks4':
                    if len(self.buffer) < 8:
                        return
                    if self.buffer[:2] != b'\x00Z':
                        raise ProbeError('socks4_connect_rejected')
                    self._finish()
                    return
                if self.state == 'method':
                    if len(self.buffer) < 2:
                        return
                    if self.buffer[:2] != b'\x05\x00':
                        raise ProbeError('socks5_auth_method_rejected')
                    del self.buffer[:2]
                    self.state = 'socks5'
                    self.transport.write(self.request)
                if self.state == 'socks5':
                    if len(self.buffer) < 4:
                        return
                    if self.buffer[:3] != b'\x05\x00\x00':
                        raise ProbeError(f'socks5_connect_rejected_{self.buffer[1]}')
                    kind = self.buffer[3]
                    if kind == 1:
                        needed = 10
                    elif kind == 4:
                        needed = 22
                    elif kind == 3:
                        if len(self.buffer) < 5:
                            return
                        if not self.buffer[4]:
                            raise ProbeError('socks5_empty_bound_hostname')
                        needed = 7 + self.buffer[4]
                    else:
                        raise ProbeError('socks5_bad_address_type')
                    if len(self.buffer) < needed:
                        return
                    self._finish()
                    return
        except (ProbeError, ValueError) as exc:
            self._finish(exc)


# ---- Shared module: response_transport ----

import asyncio
import errno
import re
import socket
import ssl
import time
from dataclasses import dataclass, replace
from functools import lru_cache
from urllib.parse import quote, urlsplit, urlunsplit
DEFAULT_RESPONSE_URLS = {'http': ('http://www.msftconnecttest.com/connecttest.txt', 'http://firefox-portal-detection.com/success.txt', 'http://captive.apple.com/hotspot-detect.html'), 'https': ('https://firefox-portal-detection.com/success.txt', 'https://captive.apple.com/hotspot-detect.html')}
STATUS_LINE = re.compile(b'HTTP/1\\.[01] ([0-9]{3})(?: [\\x09\\x20-\\x7e\\x80-\\xff]*)?\\r\\n\\Z')
MAX_STATUS_LINE = 4096

@dataclass(frozen=True, slots=True)
class ResponseTarget:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    socks4_host: str | None = None

@lru_cache(maxsize=64)
def response_target(url: str) -> ResponseTarget:
    if not isinstance(url, str) or not url or any((ord(c) <= 32 or ord(c) == 127 for c in url)):
        raise ValueError('Check URL must be an HTTP(S) URL without whitespace')
    u = urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username is not None or (u.password is not None) or u.fragment:
        raise ValueError('Check URL must be HTTP(S), without credentials or fragment')
    try:
        port = u.port or (443 if u.scheme == 'https' else 80)
        if u.port == 0:
            raise ValueError()
        host = u.hostname.encode('idna').decode('ascii')
        if len(host) > 253:
            raise ValueError()
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Invalid check URL host or port') from exc
    path = quote(u.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = quote(u.query, safe="/%?:@!$&'()*+,;=-._~")
    path = urlunsplit(('', '', path, query, ''))
    normalized = urlunsplit((u.scheme, _authority(host, port), path, '', ''))
    return ResponseTarget(normalized, u.scheme, host, port, path)

def response_targets(urls=None, scheme='http'):
    if scheme not in DEFAULT_RESPONSE_URLS:
        raise ValueError('response_scheme must be http or https')
    if isinstance(urls, str):
        urls = [urls]
    targets = list(dict.fromkeys((response_target(u) for u in (DEFAULT_RESPONSE_URLS[scheme] if urls is None else urls))))
    if not targets:
        raise ValueError('At least one check URL is required')
    if scheme == 'https' and any((t.scheme != 'https' for t in targets)):
        raise ValueError('HTTPS selection requires HTTPS check URLs')
    return targets

def lightweight_tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(['http/1.1'])
    return context

async def prepare_socks4_targets(targets):
    """Resolve once per judge, not once per proxy; retain original Host/SNI."""

    async def resolve(target):
        try:
            async with asyncio.timeout(2):
                addresses = await asyncio.get_running_loop().getaddrinfo(target.host, target.port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            if addresses:
                return replace(target, socks4_host=addresses[0][4][0])
        except (OSError, TimeoutError):
            pass
        return target
    return list(await asyncio.gather(*(resolve(target) for target in targets)))

@lru_cache(maxsize=128)
def response_request(target, absolute=False):
    path = target.url if absolute else target.path
    return f'GET {path} HTTP/1.1\r\nHost: {_authority(target.host, target.port)}\r\nConnection: close\r\n\r\n'.encode('ascii')

class HTTP200Protocol(asyncio.Protocol):
    """One socket, bounded parser buffers and optional MemoryBIO target TLS."""

    def __init__(self, proxy_kind, target, loop, ssl_context):
        self.kind, self.target = (proxy_kind, target)
        self.context = ssl_context
        self.future = loop.create_future()
        self.transport = None
        self.buffer = bytearray()
        self.incoming = self.outgoing = self.tls = None
        self.tls_ready = False
        self.phase = 'proxy_connect'
        self.state = 'new'
        self.interim = 0

    def connection_made(self, transport):
        self.transport = transport
        self.phase = 'proxy_handshake'
        if self.kind in ('direct', 'http', 'https'):
            if self.kind != 'direct' and self.target.scheme == 'https':
                self.state = 'connect'
                transport.write(tunnel_bytes('http', (self.target.host, self.target.port)))
            else:
                self._ready()
        elif self.kind == 'socks5':
            self.state = 'method'
            transport.write(b'\x05\x01\x00')
        elif self.kind == 'socks4':
            self.state = 'socks4'
            transport.write(tunnel_bytes('socks4', (self.target.socks4_host or self.target.host, self.target.port)))
        else:
            self._finish(ProbeError('unsupported_proxy_protocol'))

    def connection_lost(self, exc):
        if not self.future.done():
            self._finish(exc or ProbeError('proxy_closed'))

    def _finish(self, error=None):
        if not self.future.done():
            if error is not None:
                self.future.set_exception(error)
            else:
                self.future.set_result(200)
        self.buffer.clear()
        if self.transport is not None:
            self.transport.abort()

    def _flush_tls(self):
        while self.outgoing.pending:
            self.transport.write(self.outgoing.read())

    def _ready(self, leftover=b''):
        self.buffer.clear()
        if self.target.scheme == 'https':
            self.state, self.phase = ('tls', 'target_tls')
            self.incoming, self.outgoing = (ssl.MemoryBIO(), ssl.MemoryBIO())
            self.tls = self.context.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=self.target.host)
            if leftover:
                self.incoming.write(leftover)
            self._drive_tls()
        else:
            self.state, self.phase = ('response', 'http_response')
            self.transport.write(response_request(self.target, self.kind in ('http', 'https')))
            if leftover:
                self._http_data(leftover)

    def _drive_tls(self):
        try:
            if not self.tls_ready:
                self.tls.do_handshake()
                self.tls_ready = True
                self.phase = 'http_response'
                self.tls.write(response_request(self.target))
            while not self.future.done():
                data = self.tls.read(16384)
                if not data:
                    raise ProbeError('proxy_closed')
                self._http_data(data)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        finally:
            if not self.future.done():
                self._flush_tls()

    def _http_data(self, data):
        self.buffer.extend(data[:max(0, MAX_HEADERS + 1 - len(self.buffer))])
        while not self.future.done():
            end = self.buffer.find(b'\r\n')
            if end < 0:
                if len(self.buffer) > MAX_STATUS_LINE:
                    raise ProbeError('http_status_line_too_large')
                return
            if end + 2 > MAX_STATUS_LINE:
                raise ProbeError('http_status_line_too_large')
            match = STATUS_LINE.fullmatch(bytes(self.buffer[:end + 2]))
            if match is None:
                raise ProbeError('invalid_http_status')
            status = int(match[1])
            if 100 <= status < 200 and status != 101:
                header_end = self.buffer.find(b'\r\n\r\n')
                if header_end < 0:
                    if len(self.buffer) > MAX_HEADERS:
                        raise ProbeError('headers_too_large')
                    return
                self.interim += 1
                if self.interim > 4:
                    raise ProbeError('too_many_interim_responses')
                del self.buffer[:header_end + 4]
                continue
            if status != 200:
                raise ProbeError(f'http_status_{status}')
            self._finish()

    def data_received(self, data):
        if self.future.done():
            return
        try:
            if self.state == 'tls':
                self.incoming.write(data)
                self._drive_tls()
                return
            if self.state == 'response':
                self._http_data(data)
                return
            self.buffer.extend(data[:max(0, MAX_HEADERS + 1 - len(self.buffer))])
            while True:
                if self.state == 'connect':
                    end = self.buffer.find(b'\r\n\r\n')
                    if end < 0:
                        if len(self.buffer) > MAX_HEADERS:
                            raise ProbeError('headers_too_large')
                        return
                    status, _ = decode_headers(bytes(self.buffer[:end + 4]))
                    del self.buffer[:end + 4]
                    if 100 <= status < 200 and status != 101:
                        self.interim += 1
                        if self.interim > 4:
                            raise ProbeError('too_many_interim_responses')
                        continue
                    if not 200 <= status < 300:
                        raise ProbeError(f'connect_status_{status}')
                    self.interim = 0
                    self._ready(bytes(self.buffer))
                    return
                if self.state == 'method':
                    if len(self.buffer) < 2:
                        return
                    if self.buffer[:2] != b'\x05\x00':
                        raise ProbeError('socks5_auth_method_rejected')
                    del self.buffer[:2]
                    self.state = 'socks5'
                    self.transport.write(tunnel_bytes('socks5', (self.target.host, self.target.port)))
                if self.state == 'socks4':
                    if len(self.buffer) < 8:
                        return
                    if self.buffer[:2] != b'\x00Z':
                        raise ProbeError('socks4_connect_rejected')
                    self._ready(bytes(self.buffer[8:]))
                    return
                if self.state == 'socks5':
                    if len(self.buffer) < 4:
                        return
                    if self.buffer[:3] != b'\x05\x00\x00':
                        raise ProbeError(f'socks5_connect_rejected_{self.buffer[1]}')
                    atyp = self.buffer[3]
                    if atyp == 1:
                        needed = 10
                    elif atyp == 4:
                        needed = 22
                    elif atyp == 3:
                        if len(self.buffer) < 5:
                            return
                        if not self.buffer[4]:
                            raise ProbeError('socks5_empty_bound_hostname')
                        needed = 7 + self.buffer[4]
                    else:
                        raise ProbeError('socks5_bad_address_type')
                    if len(self.buffer) < needed:
                        return
                    self._ready(bytes(self.buffer[needed:]))
                    return
                return
        except (ProbeError, OSError, ValueError) as exc:
            self._finish(exc)

async def probe_response(proxy, target, *, timeout, ssl_context, connect_timeout=None):
    """Only the final website HTTP status 200 passes; no body is consumed."""
    started = time.monotonic()
    protocol = transport = writer = None
    connected, phase, engine = (False, 'proxy_connect', 'callback')
    error = os_errno = None
    status, http_status = ('http_200', None)
    limit = min(timeout, connect_timeout) if connect_timeout is not None else timeout
    try:
        async with asyncio.timeout(timeout):
            if proxy is not None and (proxy.username or proxy.password):
                import base64
                engine = 'streams'
                async with asyncio.timeout(limit):
                    reader, writer = await asyncio.open_connection(proxy.host, proxy.port, limit=MAX_HEADERS)
                connected = True
                if proxy.protocol == 'https':
                    phase = 'proxy_tls'
                    await writer.start_tls(ssl_context, server_hostname=proxy.host)
                phase = 'proxy_handshake'
                tunnel_host = target.socks4_host or target.host if proxy.protocol == 'socks4' else target.host
                await _tunnel(reader, writer, proxy, tunnel_host, target.port, target.scheme == 'https')
                if target.scheme == 'https':
                    phase = 'target_tls'
                    await writer.start_tls(ssl_context, server_hostname=target.host)
                phase = 'http_response'
                absolute = proxy.protocol in ('http', 'https') and target.scheme == 'http'
                request = response_request(target, absolute)
                if absolute:
                    auth = base64.b64encode(f'{proxy.username}:{proxy.password}'.encode())
                    request = request[:-2] + b'Proxy-Authorization: Basic ' + auth + b'\r\n\r\n'
                writer.write(request)
                await writer.drain()
                protocol = HTTP200Protocol('direct', target, asyncio.get_running_loop(), ssl_context)
                protocol.phase = phase
                while not protocol.future.done():
                    data = await reader.read(4096)
                    if not data:
                        raise ProbeError('proxy_closed')
                    protocol._http_data(data)
                await protocol.future
            else:
                loop = asyncio.get_running_loop()
                kind = proxy.protocol if proxy is not None else 'direct'
                protocol = HTTP200Protocol(kind, target, loop, ssl_context)
                host, port = (proxy.host, proxy.port) if proxy is not None else (target.host, target.port)
                outer_tls = proxy is not None and proxy.protocol == 'https'
                async with asyncio.timeout(limit):
                    transport, _ = await loop.create_connection(lambda: protocol, host, port, ssl=ssl_context if outer_tls else None, server_hostname=host if outer_tls else None)
                connected = True
                await protocol.future
            http_status = 200
    except TimeoutError:
        connected = connected or bool(protocol is not None and protocol.transport is not None)
        status = 'inconclusive'
        error = 'deadline_exceeded' if connected else 'connect_deadline_exceeded'
    except OSError as exc:
        os_errno = exc.errno
        local = exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EADDRNOTAVAIL}
        uncertain = local or exc.errno in {errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH}
        status = 'inconclusive' if uncertain else 'failed'
        error = 'local_resource_limit' if local else type(exc).__name__
    except (ProbeError, ValueError, asyncio.IncompleteReadError) as exc:
        status, error = ('failed', str(exc) if isinstance(exc, ProbeError) else type(exc).__name__)
        if error.startswith('http_status_') and error[12:].isdigit():
            http_status = int(error[12:])
    finally:
        if protocol is not None:
            if protocol.transport is not None:
                transport = protocol.transport
            phase = protocol.phase
            connected = connected or protocol.transport is not None
            if not protocol.future.done():
                protocol.future.cancel()
            elif not protocol.future.cancelled():
                protocol.future.exception()
        if transport is not None:
            transport.abort()
        if writer is not None:
            writer.close()
            writer.transport.abort()
    ok = status == 'http_200'
    return dict(proxy=proxy.uri() if proxy else 'direct', endpoint=proxy.endpoint if proxy else '', protocol=proxy.protocol if proxy else 'direct', ok=ok, status=status, validation_level='http_200_status', engine=engine, phase=phase, tcp_connected=connected, os_errno=os_errno, http_status=http_status, latency_ms=round((time.monotonic() - started) * 1000, 3), target=target.url, checked_at=time.time(), errors=[error] if error else [], tls_used=target.scheme == 'https', tls_verified=False, body_checked=False, exit_ips=[], anonymity='not_checked', cached=False, successes=int(ok), attempts=1, score=100 if ok else 0)


# ---- Shared module: supersonic ----

import asyncio
from collections import Counter, deque
import errno
import inspect
import math
import os
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit
DEFAULT_TUNNEL_TARGETS = ('httpbin.org:443', 'postman-echo.com:443', '1.1.1.1:443', '8.8.8.8:443')
DESTINATION_ERRORS = frozenset({'connect_status_400', 'connect_status_403', 'connect_status_421', 'connect_status_429', 'connect_status_500', 'connect_status_502', 'connect_status_503', 'connect_status_504', 'socks4_connect_rejected', 'socks5_connect_rejected_3', 'socks5_connect_rejected_4', 'socks5_connect_rejected_5', 'socks5_connect_rejected_6', 'socks5_connect_rejected_8'})
TRANSIENT_ERRORS = frozenset({'proxy_closed', 'ConnectionResetError', 'ConnectionAbortedError', 'BrokenPipeError', 'IncompleteReadError', 'invalid_http_headers', 'connect_status_429', 'connect_status_500', 'connect_status_502', 'connect_status_503', 'connect_status_504'})

# ---- adaptive governor (replaces static socket-budget + heapq scheduler) ----

def _is_mobile() -> bool:
    """Detect Android/Termux: LTE CGNAT has a hard ~1k-4k NAT port limit."""
    return 'ANDROID_ROOT' in os.environ or 'ANDROID_DATA' in os.environ or \
        'com.termux' in getattr(__import__('sys'), 'prefix', '')

def _raise_fd_limit(want: int) -> bool:
    """Try to raise soft fd limit toward hard limit; return True if raised."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need = want + 256
        if hard != resource.RLIM_INFINITY:
            need = min(need, hard)
        if soft != resource.RLIM_INFINITY and need > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))
            return True
    except (ImportError, OSError, ValueError):
        pass
    return False

class _AdaptiveGovernor:
    """AIMD concurrency controller.

    Replaces the static budget/heapq/grace-slot machinery.  A canary TCP
    connect to the first check target measures link health every 500 ms.
    When timeout share spikes or canary RTT jumps, concurrency halves (MD).
    When the link looks healthy and the queue is full, concurrency grows by
    ~16% (AI).  This lets a phone on LTE settle at ~100-300 while a VPS on
    fibre can reach thousands — each link self-tunes to its own ceiling.

    Key invariant: connect-only timeouts are NEVER retried.  Only tasks that
    completed a TCP connect and then stalled during the proxy handshake are
    eligible for a single retry.  This is what prevents the 32k-entry retry
    queue that caused the original hang.
    """

    TICK = 0.5          # governor sampling interval (s)
    WINDOW_MIN = 30     # minimum completions before making a concurrency decision
    BACKOFF = 0.60      # multiplicative decrease factor
    GROW_FRAC = 0.16    # additive increase fraction per tick
    GROW_MIN = 8        # minimum additive increase
    HOLD_TICKS = 4      # ticks to hold after a decrease
    DISTRESS_RTT_MUL = 3.0   # canary RTT multiple above baseline → distress
    DISTRESS_RTT_ABS = 0.15  # canary RTT absolute margin (s) above baseline
    TIMEOUT_SPIKE = 0.25     # timeout-share increase above baseline → spike

    def __init__(self, start: int, floor: int, ceiling: int, canary_addr: tuple,
                 ct_max: float = 3.5):
        self.limit = start
        self.floor = floor
        self.ceiling = ceiling
        self.canary_addr = canary_addr   # (host, port)
        self.ct_max = ct_max
        self.active = 0
        self.saturated = False           # True when queue is non-empty
        self._wake = asyncio.Event()
        # RTT tracking
        self.rtt: float | None = None
        self._base_rtt: float | None = None
        # Window counters (reset each tick)
        self._win_done = 0
        self._win_timeout = 0
        self._base_share: float | None = None
        # State machine
        self._hold = 0
        self._prev_rate: float | None = None
        self.local_errors = 0
        self.last_reason = 'init'
        self.events: Counter = Counter()

    # ---- public interface used by scheduler ----

    def connect_timeout(self) -> float:
        """Adaptive connect timeout: scales with measured canary RTT."""
        rtt = self.rtt if self.rtt is not None else 0.25
        return min(self.ct_max, max(2.0, 0.8 + 8.0 * rtt))

    def note_completion(self, *, connect_timed_out: bool) -> None:
        self._win_done += 1
        if connect_timed_out:
            self._win_timeout += 1
        self._wake.set()

    def note_local_error(self) -> None:
        self.local_errors += 1
        self._wake.set()

    async def wait_for_slot(self) -> None:
        """Block the caller until active < limit."""
        while self.active >= self.limit:
            self._wake.clear()
            await self._wake.wait()

    # ---- background canary + AIMD loop ----

    async def _canary(self) -> float | None:
        t0 = time.monotonic()
        writer = None
        try:
            async with asyncio.timeout(2.0):
                _, writer = await asyncio.open_connection(*self.canary_addr)
            rtt = time.monotonic() - t0
            self.rtt = rtt if self.rtt is None else 0.7 * self.rtt + 0.3 * rtt
            if self._base_rtt is None or rtt < self._base_rtt:
                self._base_rtt = rtt
            return rtt
        except Exception:
            return None
        finally:
            if writer is not None:
                try:
                    writer.transport.abort()
                except Exception:
                    pass

    async def run(self) -> None:
        """Runs as a background task for the lifetime of check_supersonic."""
        while True:
            await asyncio.sleep(self.TICK)
            rtt = await self._canary()
            done = self._win_done
            timeouts = self._win_timeout
            self._win_done = self._win_timeout = 0
            local, self.local_errors = self.local_errors > 0, 0

            share = timeouts / done if done >= self.WINDOW_MIN else None
            if share is not None and (self._base_share is None or share < self._base_share):
                self._base_share = share

            # Distress signals
            canary_dead = rtt is None
            rtt_spike = (self._base_rtt is not None and self.rtt is not None and
                         self.rtt > max(self.DISTRESS_RTT_MUL * self._base_rtt,
                                        self._base_rtt + self.DISTRESS_RTT_ABS))
            to_spike = (share is not None and self._base_share is not None and
                        share > self._base_share + self.TIMEOUT_SPIKE)

            if canary_dead or rtt_spike or to_spike or local:
                new = max(self.floor, int(self.limit * self.BACKOFF))
                if new != self.limit:
                    self.limit = new
                    self._hold = self.HOLD_TICKS
                    self._prev_rate = None
                    if canary_dead or rtt_spike:
                        self.last_reason = 'canary'
                    elif local:
                        self.last_reason = 'local_limit'
                    else:
                        self.last_reason = 'timeout_spike'
                    self.events[self.last_reason] += 1
            elif self._hold > 0:
                self._hold -= 1
            elif self.saturated and done >= self.WINDOW_MIN:
                rate = done / self.TICK
                # Goodput knee: stop growing if throughput stopped improving
                if self._prev_rate is not None and rate < self._prev_rate * 1.05:
                    self._hold = 6
                    self._prev_rate = None
                    self.last_reason = 'knee'
                    self.events['knee'] += 1
                else:
                    self._prev_rate = rate
                    grow = max(self.GROW_MIN, int(self.limit * self.GROW_FRAC))
                    self.limit = min(self.ceiling, self.limit + grow)
                    self.last_reason = 'grow'

            self._wake.set()

def tunnel_target(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or not value or any((ord(c) <= 32 for c in value)):
        raise ValueError('Target must be HOST:PORT or [IPv6]:PORT')
    u = urlsplit('//' + value)
    try:
        if not u.hostname or not u.port or u.username or u.password or u.path or u.query or u.fragment:
            raise ValueError()
        host = u.hostname.encode('idna').decode('ascii')
        if len(host) > 253:
            raise ValueError()
        return (host, u.port)
    except ValueError as exc:
        raise ValueError('Target must be HOST:PORT or [IPv6]:PORT (port 1..65535)') from exc

def socket_budget(requested: int) -> int:
    """Headroom against actual open descriptors; never changes OS limits."""
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY:
            try:
                opened = len(os.listdir('/proc/self/fd'))
            except OSError:
                opened = 64
            requested = min(requested, max(1, soft - opened - max(128, soft // 10)))
    except (ImportError, AttributeError, OSError, ValueError):
        pass
    try:
        import selectors
        selector = getattr(asyncio.get_running_loop(), '_selector', None)
        if isinstance(selector, selectors.SelectSelector):
            requested = min(requested, 384 if os.name == 'nt' else 512)
    except RuntimeError:
        pass
    return requested

def auto_tuning(*, prepare: bool=False) -> dict:
    """Mobile-aware automatic ceiling: respects CGNAT port limits on Android/LTE.

    On mobile, starts conservatively (64) and lets the AIMD governor find the
    true link ceiling rather than opening thousands of sockets at once and
    exhausting CGNAT port mappings.  On desktop, starts at 256 with a higher
    ceiling.  fd limit is raised before the ceiling is calculated so the
    socket_budget check sees the updated limit.
    """
    mobile = _is_mobile()
    # Raise fd limit first so socket_budget sees the real ceiling
    raised = False
    if prepare:
        raised = _raise_fd_limit(4096 if mobile else 8192)
    memory = []
    try:
        memory.append(os.sysconf('SC_AVPHYS_PAGES') * os.sysconf('SC_PAGE_SIZE'))
    except (AttributeError, ValueError, OSError):
        pass
    try:
        limit = Path('/sys/fs/cgroup/memory.max').read_text().strip()
        if limit != 'max':
            used = int(Path('/sys/fs/cgroup/memory.current').read_text())
            memory.append(max(0, int(limit) - used))
    except (OSError, ValueError):
        pass
    memory_cap = max(1, min(memory) // (8 * 65536)) if memory else 2048
    # Mobile ceiling: 2048 so governor has room to grow but won't nuke CGNAT on start
    raw_ceiling = min(2048 if mobile else 8192, memory_cap)
    ceiling = socket_budget(raw_ceiling)
    # Starting concurrency: mobile=64, desktop=256 — governor grows from here
    start = min(64 if mobile else 256, ceiling)
    return dict(concurrency=start, slow_slots=0, socket_budget=ceiling,
                process_fd_limit_raised=raised, mobile=mobile)

async def _fast_callback(callback, value):
    if callback is not None:
        result = callback(value)
        if inspect.isawaitable(result):
            await result

async def probe_tunnel(proxy: Proxy, target: tuple[str, int], *, timeout: float, ssl_context: ssl.SSLContext, connect_timeout: float | None=None) -> dict:
    started = time.monotonic()
    writer = transport = protocol = None
    phase, engine = ('proxy_connect', 'callback')
    status, error = ('tunnel_open', None)
    os_errno = None
    connected = False
    connect_limit = min(timeout, connect_timeout) if connect_timeout is not None else timeout
    try:
        async with asyncio.timeout(timeout):
            if proxy.username or proxy.password or proxy.protocol == 'https':
                engine = 'streams'
                outer_tls = proxy.protocol == 'https'
                async with asyncio.timeout(connect_limit):
                    reader, writer = await asyncio.open_connection(proxy.host, proxy.port, limit=MAX_HEADERS)
                connected = True
                if outer_tls:
                    phase = 'proxy_tls'
                    await writer.start_tls(ssl_context, server_hostname=proxy.host)
                phase = 'proxy_handshake'
                await _tunnel(reader, writer, proxy, target[0], target[1], True)
            else:
                loop = asyncio.get_running_loop()
                protocol = TunnelProtocol(proxy.protocol, target, loop)
                async with asyncio.timeout(connect_limit):
                    transport, _ = await loop.create_connection(lambda: protocol, proxy.host, proxy.port)
                connected = True
                phase = 'proxy_handshake'
                await protocol.future
    except TimeoutError:
        connected = connected or bool(protocol is not None and protocol.transport is not None)
        status = 'inconclusive'
        error = 'deadline_exceeded' if connected else 'connect_deadline_exceeded'
    except OSError as exc:
        os_errno = exc.errno
        local = exc.errno in {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EADDRNOTAVAIL}
        uncertain = local or exc.errno in {errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH}
        status, error = ('inconclusive' if uncertain else 'failed', 'local_resource_limit' if local else type(exc).__name__)
    except (ProbeError, asyncio.IncompleteReadError, ValueError) as exc:
        status, error = ('failed', str(exc) if isinstance(exc, ProbeError) else type(exc).__name__)
    finally:
        if protocol is not None:
            if protocol.transport is not None:
                transport = protocol.transport
            if not protocol.future.done():
                protocol.future.cancel()
            elif not protocol.future.cancelled():
                protocol.future.exception()
        if transport is not None:
            transport.abort()
        if writer is not None:
            writer.close()
            writer.transport.abort()
    ok = status == 'tunnel_open'
    if protocol is not None and protocol.transport is not None:
        connected = True
        phase = 'proxy_handshake'
    return dict(proxy=proxy.uri(), endpoint=proxy.endpoint, protocol=proxy.protocol, ok=ok, status=status, validation_level='proxy_reported_tunnel', engine=engine, phase=phase, tcp_connected=connected, os_errno=os_errno, latency_ms=round((time.monotonic() - started) * 1000, 3), target=f'[{target[0]}]:{target[1]}' if ':' in target[0] else f'{target[0]}:{target[1]}', checked_at=time.time(), errors=[error] if error else [], tls_verified=False, exit_ips=[], anonymity='not_checked', cached=False, successes=int(ok), attempts=1, score=100 if ok else 0)

async def _automatic_probe(proxy, destinations, index, *, timeout, ssl_context, recovery=False, previous=None):
    started = time.monotonic()
    preferred = list(range(2, 4)) if proxy.protocol == 'socks4' and len(destinations) == 4 else list(range(min(2, len(destinations))))
    first = preferred[index % len(preferred)]
    if recovery and len(destinations) > 1 and previous:
        last = previous.get('target')
        first = next((i for i in preferred if f'{destinations[i][0]}:{destinations[i][1]}' != last), first)
    order = [first] + [i for i in preferred if i != first] + [i for i in range(len(destinations)) if i not in preferred]
    targets, prior, attempts = ([], [], 0)
    for position in order:
        remaining = timeout - (time.monotonic() - started)
        if attempts and remaining <= 0.001:
            break
        destination = destinations[position]
        row = await probe_tunnel(proxy, destination, timeout=max(0.001, remaining), ssl_context=ssl_context, connect_timeout=None if recovery else min(4.0, timeout))
        attempts += 1
        targets.append(row.get('target', f'{destination[0]}:{destination[1]}'))
        target_retry = bool(DESTINATION_ERRORS.intersection(row['errors']))
        target_retry |= bool(recovery and row.get('tcp_connected') and TRANSIENT_ERRORS.intersection(row['errors']))
        if row['ok'] or not target_retry:
            break
        prior.extend(row['errors'])
    row.update(attempts=attempts, targets_attempted=targets, latency_ms=round((time.monotonic() - started) * 1000, 3), prior_errors=prior, recovery=recovery)
    if previous is not None:
        row['first_pass'] = previous
        row['attempts'] += previous['attempts']
        row['targets_attempted'] = previous['targets_attempted'] + targets
        row['prior_errors'] = previous['errors'] + prior
        row['latency_ms'] = round(previous['latency_ms'] + (time.monotonic() - started) * 1000, 3)
    return row

async def _automatic_response_probe(proxy, destinations, index, *, timeout, ssl_context, recovery=False, previous=None):
    target = destinations[(index + int(recovery)) % len(destinations)]
    row = await probe_response(proxy, target, timeout=timeout, ssl_context=ssl_context, connect_timeout=None if recovery else min(4.0, timeout))
    row.update(targets_attempted=[target.url], prior_errors=[], recovery=recovery)
    if previous is not None:
        row['first_pass'] = previous
        row['attempts'] += previous['attempts']
        row['targets_attempted'] = previous['targets_attempted'] + [target.url]
        row['prior_errors'] = previous['errors']
        row['latency_ms'] = round(previous['latency_ms'] + row['latency_ms'], 3)
    return row

def needs_recovery(row):
    """Retry uncertainty once; never retry auth denial, malformed protocol or RST refusal."""
    return row['status'] == 'inconclusive' or bool(TRANSIENT_ERRORS.intersection(row['errors']))

async def check_supersonic(proxies, *, target: str | None=None, concurrency: int | None=None, slow_slots: int | None=None, fast_window: float=0.15, timeout: float=20, rate: float=0, count: int=0, on_result=None, on_proxy=None, on_progress=None, ssl_context: ssl.SSLContext | None=None, method: str='response', check_urls=None, response_scheme: str='http', resolve_ipv4: bool=False) -> dict:  # noqa: E501
    """Adaptive AIMD-governed supersonic checker.  Public API unchanged.

    Replaces the static socket-budget + heapq-deadline scheduler with a
    closed-loop concurrency controller (_AdaptiveGovernor) that tracks canary
    RTT and per-window timeout share to find the largest concurrency the
    network path (LTE/CGNAT/home router) can actually sustain without
    saturation.

    Critical behaviour changes vs the original:
      * auto_tuning() starts at 64 on Android/Termux, 256 on desktop, and
        grows from there — never opens 4000+ sockets on LTE at t=0.
      * Pure connect timeouts are FINAL: they are NOT entered into the retry
        queue.  Only endpoints that completed a TCP handshake and then stalled
        during the proxy negotiation are retried (once).  This eliminates the
        32k-entry retry pass that caused the original hang.
      * The governor halves concurrency the moment canary RTT spikes or the
        timeout share exceeds baseline+25%, so CGNAT saturation is detected
        and backed off within ~500 ms instead of after the entire run.
      * The heapq/grace-slot/deferred machinery is removed; asyncio.wait_for
        on each task provides hard per-task deadlines natively.
      * All public parameters (concurrency, slow_slots, fast_window, rate,
        timeout, count, …) are still accepted; slow_slots and fast_window are
        silently ignored (the governor supersedes them) so existing call sites
        continue to work without changes.
    """
    if method not in ('response', 'tunnel'):
        raise ValueError('method must be response or tunnel')
    if method == 'response' and target is not None:
        raise ValueError('Use check_urls for HTTP-200 mode; HOST:PORT target is for method="tunnel"')
    destinations = (response_targets(check_urls, response_scheme) if method == 'response'
                    else [tunnel_target(target)] if target is not None
                    else [tunnel_target(t) for t in DEFAULT_TUNNEL_TARGETS])
    if method == 'response' and resolve_ipv4:
        destinations = await prepare_socks4_targets(destinations)
    probe = _automatic_response_probe if method == 'response' else _automatic_probe
    validation_level = 'http_200_status' if method == 'response' else 'proxy_reported_tunnel'

    # ---- sizing ----
    tuning = auto_tuning(prepare=concurrency is None or slow_slots is None)
    ceiling = socket_budget(tuning['socket_budget'])
    start = min(concurrency if concurrency is not None else tuning['concurrency'], ceiling)
    # slow_slots / fast_window accepted for API compat but not used by the new scheduler
    for name, value, minimum in [('count', count, 0)]:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ValueError(f'{name} must be an integer >= {minimum}')
    for name, value in [('timeout', timeout), ('rate', rate)]:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)) or (value < (0 if name == 'rate' else 0.001)):
            raise ValueError(f'Invalid {name}')

    context = ssl_context or (lightweight_tls_context() if method == 'response' else ssl.create_default_context())

    # ---- target preflight ----
    preflight = []
    if method == 'response' and check_urls is None:
        preflight = await asyncio.gather(*(probe_response(None, t, timeout=min(3.0, timeout), ssl_context=context) for t in destinations))
        healthy = [t for t, row in zip(destinations, preflight) if row['ok']]
        if healthy:
            destinations = healthy
        else:
            await _fast_callback(on_progress, '[target] direct preflight unavailable; retaining targets for proxy-path checks')

    # ---- canary address: first destination's host:port ----
    if method == 'response':
        canary_addr = (destinations[0].host, destinations[0].port)
    else:
        canary_addr = destinations[0]   # already (host, port) tuple

    # ---- governor ----
    gov = _AdaptiveGovernor(
        start=start,
        floor=16,
        ceiling=ceiling,
        canary_addr=canary_addr,
        ct_max=min(4.0, timeout),
    )
    # Warm up canary RTT (3 quick samples, non-blocking)
    for _ in range(3):
        await gov._canary()
    gov_task = asyncio.create_task(gov.run())

    # ---- incoming proxy stream ----
    completed: deque = deque()
    feeder = None
    incoming = None
    source_error: list = []
    source_done = object()
    wake = asyncio.Event()

    if hasattr(proxies, '__aiter__'):
        incoming = asyncio.Queue(maxsize=min(4096, max(64, ceiling * 2)))

        async def feed():
            try:
                async for proxy in proxies:
                    await incoming.put(proxy)
                    wake.set()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                source_error.append(exc)
            finally:
                wake.set()
            await incoming.put(source_done)
            wake.set()
        feeder = asyncio.create_task(feed())
        iterator = None
    else:
        iterator = iter(proxies)

    # ---- scheduler state ----
    active: dict = {}          # task → (sequence, proxy)
    retry_queue: list = []     # [(proxy, previous_row)] — TCP-connected stalls only
    found: set = set()
    exhausted = False
    in_retry = False
    next_start = 0.0
    next_progress = 0.0
    stats = dict(
        started=0, checked=0, passed=0, failed=0, inconclusive=0,
        peak_active=0, socket_budget=ceiling, cancelled=0,
        local_resource_errors=0, backoffs=0, recoveries=0,
        unreported_completed=0, recovery_queued=0, recovery_checked=0,
        recovered=0, probe_attempts=0, first_pass_inconclusive=0,
        slow_promotions=0,  # kept for API compat; always 0 in new scheduler
        target_preflight=[dict(url=r['target'], ok=r['ok'], errors=r['errors']) for r in preflight],
        validation_level=validation_level, method=method, target=target or 'automatic',
        process_fd_limit_raised=tuning['process_fd_limit_raised'],
        targets=([t.url for t in destinations] if method == 'response'
                 else [f'[{h}]:{p}' if ':' in h else f'{h}:{p}' for h, p in destinations]),
        mobile=tuning.get('mobile', False),
    )
    started = time.monotonic()
    error_counts: Counter = Counter()
    uncertain_counts: Counter = Counter()
    first_pass_errors: Counter = Counter()

    def on_done(task):
        completed.append(task)
        wake.set()

    await _fast_callback(on_progress,
        f"[supersonic] targets {stats['targets']}; start {start} → ceiling {ceiling} "
        f"(AIMD governor); deadline {timeout}s; mobile={stats['mobile']}")

    try:
        while active or not exhausted or retry_queue:
            now = time.monotonic()

            # ---- drain completed tasks ----
            while completed:
                task = completed.popleft()
                if task not in active:
                    continue
                sequence, proxy = active.pop(task)
                gov.active -= 1
                gov._wake.set()

                if task.cancelled():
                    continue
                exc = task.exception()
                if exc is not None:
                    error_counts[type(exc).__name__] += 1
                    stats['checked'] += 1
                    continue

                row = task.result()
                is_recovery = row.get('recovery', False)
                stats['probe_attempts'] += row.get('attempts', 1)

                if is_recovery:
                    stats['recovery_checked'] += 1
                    stats['inconclusive'] -= 1
                    stats['recovered'] += bool(row['ok'])
                else:
                    stats['checked'] += 1
                    first_pass_errors.update(row['errors'])
                    stats['first_pass_inconclusive'] += row['status'] == 'inconclusive'

                # Local resource errors → governor, re-queue without counting
                if 'local_resource_limit' in row['errors']:
                    gov.note_local_error()
                    stats['local_resource_errors'] += 1
                    if not is_recovery:
                        stats['checked'] -= 1
                    # Re-queue so the proxy gets another chance after backoff
                    if not is_recovery:
                        if incoming is not None:
                            # async stream: put back at front isn't possible, just skip
                            pass
                        elif iterator is not None:
                            # sync list: we don't track position, so just skip
                            pass
                    continue

                # Canary / timeout accounting
                connect_timed_out = (row.get('status') == 'inconclusive' and
                                     not row.get('tcp_connected', False) and
                                     'deadline_exceeded' not in ''.join(row.get('errors', [])))
                gov.note_completion(connect_timed_out=connect_timed_out)

                # Retry logic: ONLY endpoints that connected but stalled.
                # Pure connect timeouts (tcp_connected=False) are FINAL — never retried.
                # This is the key fix: the original retried everything, creating the 32k hang.
                stalled_after_connect = (not is_recovery
                                         and needs_recovery(row)
                                         and row.get('tcp_connected', False))
                if stalled_after_connect:
                    previous = {key: row.get(key) for key in ('errors', 'phase', 'tcp_connected', 'os_errno', 'target')}
                    previous.update(attempts=row.get('attempts', 1),
                                    latency_ms=row.get('latency_ms', 0),
                                    targets_attempted=row.get('targets_attempted', []))
                    retry_queue.append((proxy, previous))
                    stats['recovery_queued'] += 1
                    stats['inconclusive'] += 1
                    continue

                if DESTINATION_ERRORS.intersection(row['errors']) or TRANSIENT_ERRORS.intersection(row['errors']):
                    row['status'] = 'inconclusive'
                stats['failed'] += row['status'] == 'failed'
                stats['inconclusive'] += row['status'] == 'inconclusive'
                error_counts.update(row['errors'])
                if row['status'] == 'inconclusive':
                    uncertain_counts.update(row['errors'])
                await _fast_callback(on_result, row)
                if row['ok'] and row['endpoint'] not in found:
                    found.add(row['endpoint'])
                    stats['passed'] = len(found)
                    await _fast_callback(on_proxy, row['endpoint'])
                if count and len(found) >= count:
                    break

            if count and len(found) >= count:
                break

            # ---- switch to retry pass once primary is drained ----
            if exhausted and not active and retry_queue and not in_retry:
                in_retry = True
                pending_retry = list(retry_queue)
                retry_queue = []
                iterator = iter(pending_retry)
                exhausted = False
                await _fast_callback(on_progress,
                    f'[supersonic recovery] {len(pending_retry)} connected-but-stalled endpoints; '
                    f'governor limit {gov.limit}')

            gov.saturated = bool(not exhausted)

            # ---- admit new tasks up to governor limit ----
            admitted = 0
            while not exhausted and gov.active < gov.limit:
                # Rate limiting (kept for API compat; default rate=0 means unlimited)
                if rate and time.monotonic() < next_start:
                    break
                try:
                    if not in_retry and incoming is not None:
                        try:
                            proxy = incoming.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        if proxy is source_done:
                            if source_error:
                                raise source_error[0]
                            exhausted = True
                            break
                        previous = None
                    else:
                        item = next(iterator)
                        if isinstance(item, tuple):
                            proxy, previous = item
                        else:
                            proxy, previous = item, None
                except StopIteration:
                    exhausted = True
                    break
                if not isinstance(proxy, Proxy):
                    raise ValueError('check_supersonic expects Proxy objects; use parse_proxy for strings')
                sequence = stats['started']
                task = asyncio.create_task(
                    probe(proxy, destinations, sequence,
                          timeout=timeout, ssl_context=context,
                          recovery=previous is not None, previous=previous))
                active[task] = (sequence, proxy)
                gov.active += 1
                task.add_done_callback(on_done)
                stats['started'] += 1
                stats['peak_active'] = max(stats['peak_active'], gov.active)
                if rate:
                    next_start = time.monotonic() + 1.0 / rate
                admitted += 1
                if admitted >= 64:
                    break

            now = time.monotonic()
            if now >= next_progress:
                elapsed = max(now - started, 0.001)
                stage = 'recovery' if in_retry else 'primary'
                rtt_ms = f'{gov.rtt * 1000:.0f}ms' if gov.rtt is not None else 'n/a'
                await _fast_callback(on_progress,
                    f"[supersonic {stage}] {stats['checked']} checked; {stats['passed']} passed; "
                    f"{stats['inconclusive']} inconclusive/pending; {stats['recovered']} recovered; "
                    f"{gov.active} active; {stats['checked'] / elapsed:.0f}/s; "
                    f"limit {gov.limit} ({gov.last_reason}); canary {rtt_ms}")
                next_progress = now + 1

            if exhausted and not active:
                if retry_queue:
                    continue
                break
            if completed:
                continue

            wake.clear()
            if completed:
                continue
            try:
                async with asyncio.timeout(0.5):
                    await wake.wait()
            except TimeoutError:
                pass

    finally:
        gov_task.cancel()
        if feeder is not None:
            feeder.cancel()
            await asyncio.gather(feeder, return_exceptions=True)
            close = getattr(proxies, 'aclose', None)
            if close is not None:
                await close()
        stats['cancelled'] = sum(not task.done() for task in active)
        stats['unreported_completed'] = sum(task.done() for task in active)
        for task in active:
            task.cancel()
        await asyncio.gather(gov_task, *active, return_exceptions=True)

    stats['errors'] = dict(error_counts)
    stats['inconclusive_errors'] = dict(uncertain_counts)
    stats['first_pass_errors'] = dict(first_pass_errors)
    stats['pending_recovery'] = stats['recovery_queued'] - stats['recovery_checked']
    stats['seconds'] = time.monotonic() - started
    stats['final_socket_budget'] = gov.limit
    stats['discovery_connect_timeout'] = gov.connect_timeout()
    stats['checks_per_second'] = stats['checked'] / max(stats['seconds'], 1e-6)
    stats['governor'] = dict(final_limit=gov.limit, ceiling=ceiling,
                             base_rtt_ms=round((gov._base_rtt or 0) * 1000),
                             events=dict(gov.events))
    await _fast_callback(on_progress,
        f"[supersonic done] {stats['checked']} checked; {stats['passed']} passes; "
        f"{stats['inconclusive']} inconclusive; {stats['checks_per_second']:.0f}/s")
    await _fast_callback(on_progress,
        f"[supersonic diagnostics] {stats['probe_attempts']} probe attempts; "
        f"{stats['recovered']} recovered; {stats['local_resource_errors']} local resource errors; "
        f"governor {stats['governor']}; final errors {dict(error_counts)}")
    return stats


# ---- Shared module: api ----

import asyncio
import hashlib
import inspect
import json
import math
import random
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

class _SourceRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urlsplit(newurl)
        if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password or (urlsplit(req.full_url).scheme == 'https' and u.scheme != 'https'):
            raise ValueError('Unsafe source redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def _download_source(url: str, timeout: float, max_bytes: int) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SourceRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'ProxyForge-Mobile/1.2 public-list-reader', 'Accept-Encoding': 'identity'})
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError(f'source_http_{response.status}')
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError('source_too_large')
    return body.decode('utf-8-sig', errors='replace')

async def _callback(callback, value):
    if callback is not None:
        result = callback(value)
        if inspect.isawaitable(result):
            await result

def _number(name, value, *, minimum=0, integer=False):
    if isinstance(value, bool) or (integer and (not isinstance(value, int))):
        raise ValueError(f"{name} must be {('an integer' if integer else 'a number')}")
    if not isinstance(value, (int, float)) or not math.isfinite(value) or value < minimum:
        raise ValueError(f'{name} must be finite and >= {minimum}')

async def _stream_candidates(selected, input_files, *, max_candidates, max_source_bytes, source_timeout, fetch_concurrency, allow_private, ipv4_only, proxy_type, seed, on_progress):
    """Bounded ingestion: checks start before slower source downloads finish."""
    pending = asyncio.Queue(maxsize=2048)
    seen, errors = (set(), [])
    sentinel = object()
    completed = failed = 0
    groups = {}
    for row in selected.values():
        groups.setdefault(row['url'], []).append(row)
    jobs = asyncio.Queue()
    for group in groups.values():
        jobs.put_nowait(group)

    async def publish(text, row):

        def parse_batch():
            parsed = extract(text, selected_hint(row['protocol'], proxy_type), row['format'], allow_private=allow_private, limit=max_candidates, proxy_type=proxy_type)
            random.Random(seed).shuffle(parsed)
            return parsed
        parsed = await asyncio.to_thread(parse_batch)
        for proxy in parsed:
            if len(seen) >= max_candidates:
                break
            if proxy in seen or not candidate_matches(proxy, proxy_type) or proxy.username or proxy.password or (ipv4_only and ':' in proxy.host):
                continue
            seen.add(proxy)
            await pending.put(proxy)

    async def worker():
        nonlocal completed, failed
        while len(seen) < max_candidates:
            try:
                group = jobs.get_nowait()
            except asyncio.QueueEmpty:
                return
            error = None
            try:
                text = await asyncio.to_thread(_download_source, group[0]['url'], source_timeout, max_source_bytes)
                for row in group:
                    await publish(text, row)
            except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                error = type(exc).__name__
                failed += 1
            finally:
                completed += 1
                jobs.task_done()
            await _callback(on_progress, f'[source {completed}/{len(groups)}] {len(seen)} candidates streaming' + (f'; {error}' if error else ''))

    async def produce():
        tasks = []
        try:
            for path in input_files:
                path = Path(path)
                if path.stat().st_size > max_source_bytes:
                    raise ValueError(f'Input exceeds max_source_bytes: {path}')
                text = await asyncio.to_thread(path.read_text, encoding='utf-8-sig')
                await publish(text, dict(protocol='auto', format='auto'))
            tasks = [asyncio.create_task(worker()) for _ in range(min(fetch_concurrency, len(groups)))]
            await asyncio.gather(*tasks)

            def fingerprint_batch():
                return hashlib.sha256('\n'.join(sorted((p.uri() for p in seen))).encode()).hexdigest()
            fingerprint = await asyncio.to_thread(fingerprint_batch)
            await _callback(on_progress, f'[candidate set] {len(seen)} streamed; sha256 {fingerprint}; seed {seed}; {failed} source errors')
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            errors.append(exc)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        await pending.put(sentinel)
    producer = asyncio.create_task(produce())
    try:
        while True:
            proxy = await pending.get()
            if proxy is sentinel:
                if errors:
                    raise errors[0]
                break
            yield proxy
    finally:
        producer.cancel()
        await asyncio.gather(producer, return_exceptions=True)

async def get_proxies_async(proxy_type: str='socks5', *, count: int=0, check: bool=True, sources=None, expanded: bool=False, input_files=(), concurrency: int | None=None, fetch_concurrency: int=6, timeout: float=5.0, source_timeout: float=12.0, max_candidates: int | None=None, max_source_bytes: int=12000000, rate: float=20.0, checks: int=1, quorum: int | None=None, judges=None, allow_http_judge: bool=False, allow_private: bool=False, ipv4_only: bool=True, seed: int=42, on_progress=None, on_proxy=None, ssl_context: ssl.SSLContext | None=None, supersonic: bool=False, target: str | None=None, fast_window: float=0.15, slow_slots: int | None=None, tunnel_timeout: float=20.0, tunnel_rate: float=0, on_result=None, check_urls=None, supersonic_method: str='response') -> list[str]:
    """Return up to count unique unauthenticated IP:PORT entries.

    The default count=0 means all passes within max_candidates. check=False returns
    unverified candidates. HTTPS means HTTP-family CONNECT with a verified
    HTTPS judge; explicit https:// input retains TLS-to-proxy semantics.
    IPv4 is the default for unambiguous plain IP:PORT output. ipv4_only=False
    also permits bracketed [IPv6]:PORT. Source/probe errors do not fall back
    to direct requests. Verified-mode judge preflight failure raises RuntimeError.

    supersonic=True selects minimal HTTP-200 evidence by default. HTTP and
    SOCKS selections use plain HTTP connectivity pages; HTTPS selection uses
    an HTTPS request through CONNECT. Only the final website status 200 passes.
    No body, echo, anonymity or certificate verification is performed by
    default. check_urls=["https://example.org/tiny"] overrides built-in pages.
    supersonic_method="tunnel" retains legacy CONNECT-only semantics and accepts
    target="HOST:PORT". Its successes are labelled proxy_reported_tunnel.
    Concurrency/grace slots are sized automatically. The default cap is 250000.
    Collection streams into checking with bounded queues and exact deduplication.
    Slow connected attempts retain their full deadline; transient uncertainties
    get one deferred recovery. tunnel_timeout (20s per pass), tunnel_rate
    (0/unlimited), slow_slots and fast_window configure either fast method.
    timeout/rate/checks/quorum/judges configure normal verified mode instead.
    on_result receives final diagnostics, including failed/inconclusive checks.

    Custom sources are dictionaries with url/protocol/format/repository,
    matching the full program's registry. Passing [] disables remote sources.
    Progress and proxy callbacks may be synchronous or asynchronous.
    No files are written unless the caller writes them in a callback.
    """
    if supersonic:
        if not check:
            raise ValueError('supersonic and check=False are mutually exclusive')
        if target is not None:
            tunnel_target(target)
            if supersonic_method != 'tunnel':
                raise ValueError('Use check_urls for HTTP-200 mode, or supersonic_method="tunnel" with target')
    if not supersonic and concurrency is None:
        concurrency = 80
    if max_candidates is None:
        max_candidates = 250000 if supersonic else 20000
    proxy_type = normalize_type(proxy_type)
    for name, value in (('count', count), ('max_candidates', max_candidates), ('concurrency', concurrency), ('fetch_concurrency', fetch_concurrency), ('max_source_bytes', max_source_bytes), ('checks', checks)):
        if not (name == 'concurrency' and value is None and supersonic):
            _number(name, value, minimum=0 if name == 'count' else 1, integer=True)
    for name, value in (('timeout', timeout), ('source_timeout', source_timeout)):
        _number(name, value, minimum=0.001)
    _number('rate', rate)
    quorum = checks if quorum is None else quorum
    _number('quorum', quorum, minimum=1, integer=True)
    if quorum > checks:
        raise ValueError('quorum must not exceed checks')
    if proxy_type == 'https' and allow_http_judge:
        raise ValueError('HTTPS selection requires HTTPS judges')
    if not check and on_progress:
        await _callback(on_progress, 'Scrape-only: returned entries have not been checked.')
    registry = source_catalog(expanded) if sources is None else list(sources)
    selected = {}
    for row in registry:
        if not isinstance(row, dict):
            raise ValueError('Each source must be a dictionary')
        url = row.get('url', '')
        u = urlsplit(url)
        if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password:
            raise ValueError('Invalid source URL')
        hint, fmt = (row.get('protocol', 'auto'), row.get('format', 'auto'))
        if hint not in ('auto', 'http', 'https', 'socks4', 'socks5'):
            raise ValueError('Invalid source protocol')
        if fmt not in ('auto', 'text', 'csv', 'csv_rows', 'json', 'html', 'web_html'):
            raise ValueError('Invalid source format')
        if source_matches(hint, proxy_type):
            selected[url, hint, fmt] = dict(row, protocol=hint, format=fmt)
    if supersonic:
        scheme = 'https' if proxy_type == 'https' else 'http'
        if supersonic_method == 'response':
            response_targets(check_urls, scheme)
        endpoints = []

        async def receive(endpoint):
            endpoints.append(endpoint)
            await _callback(on_proxy, endpoint)
        incoming = _stream_candidates(selected, input_files, max_candidates=max_candidates, max_source_bytes=max_source_bytes, source_timeout=source_timeout, fetch_concurrency=fetch_concurrency, allow_private=allow_private, ipv4_only=ipv4_only, proxy_type=proxy_type, seed=seed, on_progress=on_progress)
        await check_supersonic(incoming, target=target, concurrency=concurrency, slow_slots=slow_slots, fast_window=fast_window, timeout=tunnel_timeout, rate=tunnel_rate, count=count, on_proxy=receive, on_result=on_result, on_progress=on_progress, ssl_context=ssl_context, method=supersonic_method, check_urls=check_urls, response_scheme=scheme, resolve_ipv4=proxy_type in ('socks4', 'all'))
        return endpoints
    candidates = {}
    source_errors = 0

    def collect(text, row):
        proxies = extract(text, selected_hint(row['protocol'], proxy_type), row['format'], allow_private=allow_private, limit=max_candidates, proxy_type=proxy_type)
        for proxy in proxies:
            if not candidate_matches(proxy, proxy_type) or proxy.username or proxy.password or (ipv4_only and ':' in proxy.host):
                continue
            if len(candidates) < max_candidates or proxy in candidates:
                candidates[proxy] = None
    queue = asyncio.Queue()
    groups = {}
    for row in selected.values():
        groups.setdefault(row['url'], []).append(row)
    for group in groups.values():
        queue.put_nowait(group)
    completed = 0

    async def fetch_worker():
        nonlocal source_errors, completed
        while True:
            try:
                group = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            error = None
            try:
                text = await asyncio.to_thread(_download_source, group[0]['url'], source_timeout, max_source_bytes)
                for row in group:
                    collect(text, row)
            except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
                error = type(exc).__name__
                source_errors += 1
            finally:
                completed += 1
                queue.task_done()
            await _callback(on_progress, f'[source {completed}/{len(groups)}] {len(candidates)} candidates' + (f'; {error}' if error else ''))
    tasks = [asyncio.create_task(fetch_worker()) for _ in range(min(fetch_concurrency, len(groups)))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    for path in input_files:
        path = Path(path)
        if path.stat().st_size > max_source_bytes:
            raise ValueError(f'Input exceeds max_source_bytes: {path}')
        collect(path.read_text(encoding='utf-8-sig'), {'protocol': 'auto', 'format': 'auto'})
    await _callback(on_progress, f'[collected] {len(candidates)} protocol candidates; {source_errors} failed source downloads')
    items = list(candidates)
    random.Random(seed).shuffle(items)
    fingerprint = hashlib.sha256('\n'.join(sorted((p.uri() for p in items))).encode()).hexdigest()
    await _callback(on_progress, f'[candidate set] {len(items)} candidates; sha256 {fingerprint}; shuffle seed {seed}')
    if not items:
        return []
    if not check:
        endpoints = list(dict.fromkeys((p.endpoint for p in items)))
        if count:
            endpoints = endpoints[:count]
        for endpoint in endpoints:
            await _callback(on_proxy, endpoint)
        return endpoints
    checker = Checker(judges or DEFAULT_JUDGES, timeout=timeout, checks=checks, quorum=quorum, rate=rate, allow_http=allow_http_judge, ssl_context=ssl_context)
    await checker.prepare()
    iterator = iter(items)
    found = {}
    done = 0
    stop = asyncio.Event()

    async def check_worker():
        nonlocal done
        for proxy in iterator:
            if stop.is_set():
                return
            row = await checker.check(proxy)
            done += 1
            if row['ok'] and proxy.endpoint not in found and (not count or len(found) < count):
                found[proxy.endpoint] = None
                await _callback(on_proxy, proxy.endpoint)
                if count and len(found) >= count:
                    stop.set()
            if done % 25 == 0 or done == len(items):
                await _callback(on_progress, f'[check] {done}/{len(items)} checked; {len(found)} passed')
    workers = [asyncio.create_task(check_worker()) for _ in range(min(concurrency, len(items)))]
    completed_checks = asyncio.gather(*workers)
    stop_waiter = asyncio.create_task(stop.wait())
    try:
        await asyncio.wait([completed_checks, stop_waiter], return_when=asyncio.FIRST_COMPLETED)
        if completed_checks.done():
            await completed_checks
        else:
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
    finally:
        for task in workers:
            task.cancel()
        stop_waiter.cancel()
        await asyncio.gather(*workers, stop_waiter, return_exceptions=True)
        if not completed_checks.done():
            completed_checks.cancel()
        await asyncio.gather(completed_checks, return_exceptions=True)
    await _callback(on_progress, f'[done] {len(found)} {proxy_type} proxies passed')
    return list(found)

def get_proxies(proxy_type: str='socks5', **kwargs) -> list[str]:
    """Synchronous wrapper. Use get_proxies_async in an active event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(get_proxies_async(proxy_type, **kwargs))
    raise RuntimeError('An event loop is running; await get_proxies_async(...) instead')


# ---- Embedded source registry ----

DEFAULT_SOURCES = [{'url': 'https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'ProxyScraper/ProxyScraper'},
 {'url': 'https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'ProxyScraper/ProxyScraper'},
 {'url': 'https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'ProxyScraper/ProxyScraper'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'ALIILAPRO/Proxy'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'ALIILAPRO/Proxy'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'ALIILAPRO/Proxy'},
 {'url': 'https://raw.githubusercontent.com/Skillter/ProxyGather/master/proxies/working-proxies-http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'sunny9577/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/Skillter/ProxyGather/master/proxies/working-proxies-socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'sunny9577/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/Skillter/ProxyGather/master/proxies/working-proxies-socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'sunny9577/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/claude89757/free_https_proxies/main/https_proxies.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'claude89757/free_https_proxies'},
 {'url': 'https://raw.githubusercontent.com/claude89757/free_https_proxies/main/isz_https_proxies.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'claude89757/free_https_proxies'},
 {'url': 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'hproxy-com/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'hproxy-com/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'hproxy-com/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'hproxy-com/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'vmheaven/VMHeaven.io-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'vmheaven/VMHeaven.io-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'vmheaven/VMHeaven.io-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'vmheaven/VMHeaven.io-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'databay-labs/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'databay-labs/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'databay-labs/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'databay-labs/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'xyzs996/free-proxy-health-list'},
 {'url': 'https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'xyzs996/free-proxy-health-list'},
 {'url': 'https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'xyzs996/free-proxy-health-list'},
 {'url': 'https://raw.githubusercontent.com/xyzs996/free-proxy-health-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'xyzs996/free-proxy-health-list'},
 {'url': 'https://raw.githubusercontent.com/6yyn/free-proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': '6yyn/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/6yyn/free-proxy-list/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': '6yyn/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'proxmint/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'proxmint/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'proxmint/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'proxmint/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'roosterkid/openproxylist'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'roosterkid/openproxylist'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'roosterkid/openproxylist'},
 {'url': 'https://raw.githubusercontent.com/MrMarble/proxy-list/main/all.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'MrMarble/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'VPSLabCloud/VPSLab-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'VPSLabCloud/VPSLab-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'VPSLabCloud/VPSLab-Free-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/pmix_checked.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://www.sslproxies.org/',
  'protocol': 'https',
  'format': 'html',
  'repository': 'jundymek/free-proxy'},
 {'url': 'https://www.us-proxy.org/',
  'protocol': 'https',
  'format': 'html',
  'repository': 'jundymek/free-proxy'},
 {'url': 'https://free-proxy-list.net/uk-proxy.html',
  'protocol': 'https',
  'format': 'html',
  'repository': 'jundymek/free-proxy'},
 {'url': 'https://free-proxy-list.net/',
  'protocol': 'https',
  'format': 'html',
  'repository': 'jundymek/free-proxy'},
 {'url': 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/http/data.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'ProxyScrape/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/https/data.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'ProxyScrape/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/socks4/data.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'ProxyScrape/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/socks5/data.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'ProxyScrape/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'iplocate/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'iplocate/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'iplocate/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'iplocate/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTP.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'Argh94/Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTPS.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'Argh94/Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'Argh94/Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'Argh94/Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/http_proxies.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'dpangestuw/Free-Proxy'},
 {'url': 'https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks4_proxies.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'dpangestuw/Free-Proxy'},
 {'url': 'https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks5_proxies.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'dpangestuw/Free-Proxy'},
 {'url': 'https://raw.githubusercontent.com/fmw86/free-proxy-pool/main/http_alive.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'fmw86/free-proxy-pool'},
 {'url': 'https://raw.githubusercontent.com/fmw86/free-proxy-pool/main/socks4_alive.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'fmw86/free-proxy-pool'},
 {'url': 'https://raw.githubusercontent.com/fmw86/free-proxy-pool/main/socks5_alive.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'fmw86/free-proxy-pool'},
 {'url': 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'SoliSpirit/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'SoliSpirit/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'SoliSpirit/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'SoliSpirit/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/maximilianfeix/proxy-scraper/proxy-list/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'maximilianfeix/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/maximilianfeix/proxy-scraper/proxy-list/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'maximilianfeix/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/maximilianfeix/proxy-scraper/proxy-list/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'maximilianfeix/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/maximilianfeix/proxy-scraper/proxy-list/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'maximilianfeix/proxy-scraper'},
 {'url': 'https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'theriturajps/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Mohammedcha/ProxRipper/main/full_proxies/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'Mohammedcha/ProxRipper'},
 {'url': 'https://raw.githubusercontent.com/Mohammedcha/ProxRipper/main/full_proxies/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'Mohammedcha/ProxRipper'},
 {'url': 'https://raw.githubusercontent.com/Mohammedcha/ProxRipper/main/full_proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'Mohammedcha/ProxRipper'},
 {'url': 'https://raw.githubusercontent.com/Mohammedcha/ProxRipper/main/full_proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'Mohammedcha/ProxRipper'},
 {'url': 'https://raw.githubusercontent.com/proxio-io/proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'proxio-io/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxio-io/proxy-list/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'proxio-io/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'proxio-io/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'proxio-io/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/afr0700/ProxyList/main/ProxyList.txt',
  'protocol': 'auto',
  'format': 'csv_rows',
  'repository': 'afr0700/ProxyList'},
 {'url': 'https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'proxy-free/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'proxy-free/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'proxy-free/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'komutan234/Proxy-List-Free'},
 {'url': 'https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'komutan234/Proxy-List-Free'},
 {'url': 'https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'komutan234/Proxy-List-Free'},
 {'url': 'https://raw.githubusercontent.com/Bes-js/public-proxy-list/main/proxies.txt',
  'protocol': 'auto',
  'format': 'text',
  'repository': 'Bes-js/public-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'litportnet/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'litportnet/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'litportnet/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'litportnet/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/z3a4/free-proxy-list/main/proxies/unchecked/http-proxies.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'z3a4/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/z3a4/free-proxy-list/main/proxies/unchecked/https-proxies.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'z3a4/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/z3a4/free-proxy-list/main/proxies/unchecked/socks4-proxies.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'z3a4/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/z3a4/free-proxy-list/main/proxies/unchecked/socks5-proxies.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'z3a4/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Ch4120N/Ch4120N-Proxy-List/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'Ch4120N/Ch4120N-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/Ch4120N/Ch4120N-Proxy-List/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'Ch4120N/Ch4120N-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/Ch4120N/Ch4120N-Proxy-List/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'Ch4120N/Ch4120N-Proxy-List'},
 {'url': 'https://raw.githubusercontent.com/Pxys-io/DailyProxyList/main/working_proxies.txt',
  'protocol': 'auto',
  'format': 'text',
  'repository': 'Pxys-io/DailyProxyList'},
 {'url': 'https://raw.githubusercontent.com/trio666/proxy-checker/main/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'trio666/proxy-checker'},
 {'url': 'https://raw.githubusercontent.com/trio666/proxy-checker/main/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'trio666/proxy-checker'},
 {'url': 'https://raw.githubusercontent.com/trio666/proxy-checker/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'trio666/proxy-checker'},
 {'url': 'https://raw.githubusercontent.com/trio666/proxy-checker/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'trio666/proxy-checker'},
 {'url': 'https://raw.githubusercontent.com/azestkingscrown/Free_Proxy_List/main/working_proxies.txt',
  'protocol': 'auto',
  'format': 'text',
  'repository': 'azestkingscrown/Free_Proxy_List'},
 {'url': 'https://chillyproxy.com/api/tools/free-proxies/details?protocol=all&country=ALL&limit=100',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:ChillyProxy'},
 {'url': 'https://freeproxydb.com/api/proxy/search?protocol=http,socks4,socks5&page_index=1&page_size=100',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:FreeProxyDB'},
 {'url': 'https://www.freeproxy.world/',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeProxyWorld'},
 {'url': 'https://www.freevpnnode.com/free-proxy?page=1',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeVPNNode'},
 {'url': 'https://api.89ip.cn/tqdl.html?api=1&num=200&port=&address=&isp=',
  'protocol': 'http',
  'format': 'text',
  'repository': 'web:89IP'},
 {'url': 'https://www.kuaidaili.com/free/inha/1/',
  'protocol': 'http',
  'format': 'web_html',
  'repository': 'web:Kuaidaili'},
 {'url': 'https://papi.proxiware.com/proxies?page=1&country=&protocol=&anonymity=&speed=',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:Proxiware'},
 {'url': 'https://proxy-daily.com/api/serverside/proxies?draw=1&start=0&length=100',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:ProxyDaily'},
 {'url': 'https://proxydb.net/?offset=0',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyDB'},
 {'url': 'https://proxylister.com/api/v1/proxies?limit=500&page=1&sort=-last_checked_at',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:ProxyLister'},
 {'url': 'https://roundproxies.com/api/get-free-proxies/?limit=100&page=1&sort_by=lastChecked&sort_type=desc',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:Roundproxies'},
 {'url': 'https://proxy.scdn.io/api/get_proxy.php?protocol=socks5&count=20&page=1',
  'protocol': 'socks5',
  'format': 'json',
  'repository': 'web:SCDN'},
 {'url': 'https://advanced.name/freeproxy?page=1',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:AdvancedName'},
 {'url': 'https://proxyverity.com/free-proxy-list/?page=1',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyVerity'},
 {'url': 'https://proxymania.su/free-proxy',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyMania'},
 {'url': 'https://proxyelite.info/free-proxy-list/',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyElite'},
 {'url': 'https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1',
  'protocol': 'http',
  'format': 'web_html',
  'repository': 'web:ProxyListPlus'},
 {'url': 'https://proxy-list.org/english/index.php',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyListOrg'},
 {'url': 'http://free-proxy.cz/en/',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeProxyCZ'},
 {'url': 'https://www.proxy-radar.com/free-proxy',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyRadar'}]


# ---- Embedded source registry ----

EXPANDED_SOURCES = [{'url': 'https://openproxylist.xyz/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://openproxylist.xyz/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://openproxylist.xyz/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.socks-proxy.net/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.us-proxy.org/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.sslproxies.org/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.google-proxy.net/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://free-proxy-list.net/anonymous-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://free-proxy-list.net/uk-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://free-proxy-list.net/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://geonode.com/free-proxy-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://spys.one/en/', 'protocol': 'auto', 'format': 'auto', 'repository': 'Skillter/ProxyGather'},
 {'url': 'https://spys.one/en/free-proxy-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://spys.me/proxy.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://spys.me/socks.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://vpnoverview.com/privacy/anonymous-browsing/free-proxy-servers/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://hidemy.name/en/proxy-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxynova.com/proxy-server-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://free-proxy-list.com/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://anonymouse.cz/proxy-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.coderduck.com/free-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxyrack.com/free-proxy-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxy-list.download',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxy.lunaproxy.com/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://webanetlabs.net/publ/23',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://webanetlabs.net/publ/24',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://webanetlabs.net/publ/28',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://static.fatezero.org/tmp/proxy.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxymist.com/protocols/http/',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxymist.com/protocols/socks4/',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxymist.com/protocols/socks5/',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxymist.com/anonymity/elite/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxymist.com/anonymity/anonymous/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://cyber-gateway.net/nfo/333-free-proxy-list-txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://cyber-gateway.net/get-proxy/free-proxy/57-free-proxy-google',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://cyber-gateway.net/get-proxy/free-proxy/56-free-socks-proxy',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://cyber-gateway.net/get-proxy/free-proxy/24-free-http-proxy',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.duplichecker.com/free-proxy-list.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/http-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/full-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/anonymous-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/distorting-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/elite-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/https-ssl-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/mikrotik-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/socks-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/squid-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxypremium.top/top-country-proxy-list',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://sockslist.us/Api?request=display&country=all&level=all&token=free',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-http-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-https-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-socks-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock4-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock5-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/us-free-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/gb-free-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-http-proxy-list.html||{"cookie":"anonymity=elite"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-https-proxy-list.html||{"cookie":"anonymity=elite"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-socks-proxy-list.html||{"cookie":"anonymity=elite"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock4-proxy-list.html||{"cookie":"anonymity=elite"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock5-proxy-list.html||{"cookie":"anonymity=elite"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-http-proxy-list.html||{"cookie":"anonymity=anonymous"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-https-proxy-list.html||{"cookie":"anonymity=anonymous"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-socks-proxy-list.html||{"cookie":"anonymity=anonymous"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock4-proxy-list.html||{"cookie":"anonymity=anonymous"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock5-proxy-list.html||{"cookie":"anonymity=anonymous"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-http-proxy-list.html||{"cookie":"anonymity=transparent"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-https-proxy-list.html||{"cookie":"anonymity=transparent"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-socks-proxy-list.html||{"cookie":"anonymity=transparent"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock4-proxy-list.html||{"cookie":"anonymity=transparent"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://proxyhub.me/en/all-sock5-proxy-list.html||{"cookie":"anonymity=transparent"}',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-proxy-list.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-elite-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-anonymous-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-transparent-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-socks-4-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-socks-5-proxy.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.my-proxy.com/free-proxy-list-{page}.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://ab57.ru/proxylist.html',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://ab57.ru/downloads/proxyold.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://ab57.ru/downloads/proxylist.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/https-ssl.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/elite.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/anonymous.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://freeproxyupdate.com/files/txt/transparent.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxy-list.download/api/v2/get?l=en&t=http',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxy-list.download/api/v2/get?l=en&t=https',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxy-list.download/api/v2/get?l=en&t=socks4',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.proxy-list.download/api/v2/get?l=en&t=socks5',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://github.com/zloi-user/hideip.me/raw/refs/heads/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://github.com/zloi-user/hideip.me/raw/refs/heads/master/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://github.com/zloi-user/hideip.me/raw/refs/heads/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://github.com/zloi-user/hideip.me/raw/refs/heads/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://github.com/zloi-user/hideip.me/raw/refs/heads/master/connect.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestProxy/proxy.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/refs/heads/main/online-proxies/txt/proxies.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/xResults/RAW.txt',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/ipv4.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/dlya-parsinga.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/elite.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/anonymous.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/socks.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/socks4.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/socks5.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/http.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/https.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/individual-ipv4.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/packet.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://papaproxy.net/ru/packet-ipv4.php',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://www.911proxy.com/detection/proxyList?limit=500&page={page}&sort_by=lastChecked&sort_type=desc',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://premiumproxy.net/full-proxy-list/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://fineproxy.org/free-proxy/',
  'protocol': 'auto',
  'format': 'auto',
  'repository': 'Skillter/ProxyGather'},
 {'url': 'https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/pmix_checked.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ArteffKod/socks4/main/socks4%20proxy',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/refs/heads/main/proxylist.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/KUTlime/ProxyList/main/ProxyList.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/all.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/MrMarble/proxy-list/main/all.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/noarche/proxylist-socks5-sock4-exported-updates/main/http-online.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/http/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/unknown.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zebbern/Proxy-Scraper/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/unchecked.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/javadbazokar/PROXY-List/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/refs/heads/main/free.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/FifzzSENZE/Master-Proxy/master/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/handeveloper1/Proxy/raw/refs/heads/main/Proxies-Ercin/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fahimscirex/proxybd/refs/heads/master/proxylist/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Anonym0usWork1221/Free-Proxies/raw/refs/heads/main/proxy_files/http_proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/zenjahid/FreeProxy4u/raw/refs/heads/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/refs/heads/main/http',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/BreakingTechFr/Proxy_Free/refs/heads/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VolkanSah/Auto-Proxy-Fetcher/refs/heads/main/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/refs/heads/master/proxy_list.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/variableninja/proxyscraper/refs/heads/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/berkay-digital/Proxy-Scraper/refs/heads/main/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/proxylist/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/anonymous-proxylist/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/XigmaDev/proxy/raw/refs/heads/main/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/chekamarue/proxies/raw/refs/heads/main/https.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/chekamarue/proxies/raw/refs/heads/main/httpss.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/claude89757/free_https_proxies/raw/refs/heads/main/https_proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/claude89757/free_https_proxies/raw/refs/heads/main/isz_https_proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/joy-deploy/free-proxy-list/refs/heads/main/data/latest/types/http/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/andigwandi/free-proxy/raw/refs/heads/main/proxy_list.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/murtaja89/public-proxies/raw/refs/heads/main/proxies_all.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/parserpp/ip_ports/refs/heads/main/proxyinfo.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vadim287/free-proxy/refs/heads/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/http-proxy-list-by-EbraSha.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://rootjazz.com/proxies/proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=ipport&format=text&timeout=20000',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://proxyspace.pro/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casa-ls/proxy-list/refs/heads/main/http',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/refs/heads/main/online-proxies/txt/proxies-http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Thordata/awesome-free-proxy-list/raw/refs/heads/main/proxies/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/https.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Unstable/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Unstable/https.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Stable/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Stable/https.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_all.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_ssl.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_nossl.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_elite.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_anonymous.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_transparent.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_ssl_elite.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_ssl_anonymous.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/stormsia/proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/twj0/subseek/master/data/china_proxies/raw_china_proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hienhoceo-dpsmedia/nekobox-proxy-list/refs/heads/main/dist/debug/http-china-live.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hienhoceo-dpsmedia/nekobox-proxy-list/refs/heads/main/dist/debug/http-us.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/398001/ProxysList/refs/heads/main/http_working.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://rcloak.com/api/proxies/raw?protocol=http',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ArteffKod/socks4/main/socks4%20proxy',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/refs/heads/main/proxylist.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/im-razvan/proxy_list/main/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/noarche/proxylist-socks5-sock4-exported-updates/main/connect-online.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/https/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/unknown.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zebbern/Proxy-Scraper/main/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/unchecked.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/javadbazokar/PROXY-List/main/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/refs/heads/main/free.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/FifzzSENZE/Master-Proxy/master/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/handeveloper1/Proxy/raw/refs/heads/main/Proxies-Ercin/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Anonym0usWork1221/Free-Proxies/raw/refs/heads/main/proxy_files/https_proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/BreakingTechFr/Proxy_Free/refs/heads/main/proxies/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VolkanSah/Auto-Proxy-Fetcher/refs/heads/main/proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/refs/heads/master/proxy_list.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/berkay-digital/Proxy-Scraper/refs/heads/main/proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/proxylist/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/anonymous-proxylist/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/XigmaDev/proxy/raw/refs/heads/main/proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/chekamarue/proxies/raw/refs/heads/main/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/chekamarue/proxies/raw/refs/heads/main/httpss.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/claude89757/free_https_proxies/raw/refs/heads/main/https_proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/claude89757/free_https_proxies/raw/refs/heads/main/isz_https_proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/joy-deploy/free-proxy-list/refs/heads/main/data/latest/types/http/proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/andigwandi/free-proxy/raw/refs/heads/main/proxy_list.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/murtaja89/public-proxies/raw/refs/heads/main/proxies_all.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/dinoz0rg/proxy-list/raw/refs/heads/main/scraped_proxies/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/parserpp/ip_ports/refs/heads/main/proxyinfo.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/joy-deploy/free-proxy-list/refs/heads/main/data/{YYYY}-{MM}/{DD}/{HH/4}-00/proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://a.nodeshare.xyz/uploads/{YYYY}/{M}/{YYYY}{MM}{DD}.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/https-proxy-list-by-EbraSha.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casa-ls/proxy-list/refs/heads/main/http',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/refs/heads/main/online-proxies/txt/proxies-https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Thordata/awesome-free-proxy-list/raw/refs/heads/main/proxies/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Stable/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Stable/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Unstable/http.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Unstable/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_all.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_ssl.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_nossl.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_elite.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_anonymous.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_transparent.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_ssl_elite.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/http_ssl_anonymous.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://rcloak.com/api/proxies/raw?protocol=http',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ArteffKod/socks4/main/socks4%20proxy',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/refs/heads/main/proxylist.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/noarche/proxylist-socks5-sock4-exported-updates/main/socks4-online.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/sock4/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/unknown.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zebbern/Proxy-Scraper/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/unchecked.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/FifzzSENZE/Master-Proxy/master/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/handeveloper1/Proxy/raw/refs/heads/main/Proxies-Ercin/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fahimscirex/proxybd/refs/heads/master/proxylist/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Anonym0usWork1221/Free-Proxies/raw/refs/heads/main/proxy_files/socks4_proxies.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/zenjahid/FreeProxy4u/raw/refs/heads/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/refs/heads/main/socks4',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/BreakingTechFr/Proxy_Free/refs/heads/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VolkanSah/Auto-Proxy-Fetcher/refs/heads/main/proxies.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/refs/heads/master/proxy_list.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/variableninja/proxyscraper/refs/heads/main/proxies/socks.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/proxylist/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/anonymous-proxylist/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/joy-deploy/free-proxy-list/refs/heads/main/data/latest/types/socks4/proxies.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/murtaja89/public-proxies/raw/refs/heads/main/proxies_all.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/parserpp/ip_ports/refs/heads/main/proxyinfo.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vadim287/free-proxy/refs/heads/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/socks4-proxy-list-by-EbraSha.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casa-ls/proxy-list/refs/heads/main/socks4',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/refs/heads/main/online-proxies/txt/proxies-socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Thordata/awesome-free-proxy-list/raw/refs/heads/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Stable/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Unstable/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/socks4_all.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/stormsia/proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://rcloak.com/api/proxies/raw?protocol=socks4',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ArteffKod/socks4/main/socks4%20proxy',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/refs/heads/main/proxylist.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/noarche/proxylist-socks5-sock4-exported-updates/main/socks5-online.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/refs/heads/KangProxy/socks5/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/SevenworksDev/proxy-list/main/proxies/unknown.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/themiralay/Proxy-List-World/master/data.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/scraped_proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zebbern/Proxy-Scraper/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/unchecked.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/FifzzSENZE/Master-Proxy/master/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/handeveloper1/Proxy/raw/refs/heads/main/Proxies-Ercin/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Anonym0usWork1221/Free-Proxies/raw/refs/heads/main/proxy_files/socks5_proxies.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/zenjahid/FreeProxy4u/raw/refs/heads/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/refs/heads/main/socks5',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/BreakingTechFr/Proxy_Free/refs/heads/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VolkanSah/Auto-Proxy-Fetcher/refs/heads/main/proxies.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/refs/heads/master/proxy_list.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/variableninja/proxyscraper/refs/heads/main/proxies/socks.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/proxylist/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/iniridwanul/Hoot/refs/heads/master/anonymous-proxylist/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/joy-deploy/free-proxy-list/refs/heads/main/data/latest/types/socks5/proxies.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/murtaja89/public-proxies/raw/refs/heads/main/proxies_all.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/parserpp/ip_ports/refs/heads/main/proxyinfo.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Vadim287/free-proxy/refs/heads/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/socks5-proxy-list-by-EbraSha.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casa-ls/proxy-list/refs/heads/main/socks5',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/refs/heads/main/online-proxies/txt/proxies-socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/Thordata/awesome-free-proxy-list/raw/refs/heads/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Stable/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://github.com/proxygenerator1/ProxyGenerator/raw/refs/heads/main/Unstable/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/socks5_all.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/stormsia/proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://rcloak.com/api/proxies/raw?protocol=socks5',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/main/http',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/saisuiu/Lionkings-Http-Proxys-Proxies/main/cnfree.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
  'protocol': 'http',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.proxyscrape.com/?request=getproxies&proxytype=https&timeout=10000&country=all&ssl=all&anonymity=all',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/main/https',
  'protocol': 'https',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks4',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://www.proxy-list.download/api/v1/get?type=socks4',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://proxyspace.pro/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.openproxylist.xyz/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt',
  'protocol': 'socks4',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.openproxylist.xyz/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://proxyspace.pro/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://spys.me/socks.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt',
  'protocol': 'socks5',
  'format': 'auto',
  'repository': 'SevenworksDev/proxy-list'},
 {'url': 'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt',
  'protocol': 'http',
  'format': 'text',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/https.txt',
  'protocol': 'https',
  'format': 'text',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt',
  'protocol': 'socks4',
  'format': 'text',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt',
  'protocol': 'socks5',
  'format': 'text',
  'repository': 'gfpcom/free-proxy-list'},
 {'url': 'https://freeproxydb.com/api/proxy/search?protocol=http,socks4,socks5&page_index=2&page_size=100',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:FreeProxyDB'},
 {'url': 'https://freeproxydb.com/api/proxy/search?protocol=http,socks4,socks5&page_index=3&page_size=100',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:FreeProxyDB'},
 {'url': 'https://www.freeproxy.world/?page=2',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeProxyWorld'},
 {'url': 'https://www.freeproxy.world/?page=3',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeProxyWorld'},
 {'url': 'https://www.freevpnnode.com/free-proxy?page=2',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeVPNNode'},
 {'url': 'https://www.freevpnnode.com/free-proxy?page=3',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:FreeVPNNode'},
 {'url': 'https://papi.proxiware.com/proxies?page=2&country=&protocol=&anonymity=&speed=',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:Proxiware'},
 {'url': 'https://papi.proxiware.com/proxies?page=3&country=&protocol=&anonymity=&speed=',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:Proxiware'},
 {'url': 'https://proxydb.net/?offset=30',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyDB'},
 {'url': 'https://proxydb.net/?offset=60',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyDB'},
 {'url': 'https://proxylister.com/api/v1/proxies?limit=500&page=2&sort=-last_checked_at',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:ProxyLister'},
 {'url': 'https://proxylister.com/api/v1/proxies?limit=500&page=3&sort=-last_checked_at',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:ProxyLister'},
 {'url': 'https://roundproxies.com/api/get-free-proxies/?limit=100&page=2&sort_by=lastChecked&sort_type=desc',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:Roundproxies'},
 {'url': 'https://roundproxies.com/api/get-free-proxies/?limit=100&page=3&sort_by=lastChecked&sort_type=desc',
  'protocol': 'auto',
  'format': 'json',
  'repository': 'web:Roundproxies'},
 {'url': 'https://advanced.name/freeproxy?page=2',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:AdvancedName'},
 {'url': 'https://advanced.name/freeproxy?page=3',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:AdvancedName'},
 {'url': 'https://proxyverity.com/free-proxy-list/?page=2',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyVerity'},
 {'url': 'https://proxyverity.com/free-proxy-list/?page=3',
  'protocol': 'auto',
  'format': 'web_html',
  'repository': 'web:ProxyVerity'},
 {'url': 'https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-2',
  'protocol': 'http',
  'format': 'web_html',
  'repository': 'web:ProxyListPlus'},
 {'url': 'https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-3',
  'protocol': 'http',
  'format': 'web_html',
  'repository': 'web:ProxyListPlus'},
 {'url': 'https://proxy.scdn.io/api/get_proxy.php?protocol=http&count=20&page=1',
  'protocol': 'http',
  'format': 'json',
  'repository': 'web:SCDN'},
 {'url': 'https://proxy.scdn.io/api/get_proxy.php?protocol=socks4&count=20&page=1',
  'protocol': 'socks4',
  'format': 'json',
  'repository': 'web:SCDN'}]


def source_catalog(expanded: bool = False) -> list[dict]:
    rows = DEFAULT_SOURCES + (EXPANDED_SOURCES if expanded else [])
    return [dict(row) for row in rows]


def _mobile_types(groups):
    import re
    choices = {"1": "http", "2": "https", "3": "socks4", "4": "socks5", "5": "all"}
    selected = []
    for group in groups:
        for value in group:
            for token in re.split(r"[,\s]+", value.strip().lower()):
                if not token:
                    continue
                token = choices.get(token, token)
                if token not in PROXY_TYPES:
                    raise ValueError(f"Invalid proxy type: {token}; choose http, https, socks4, socks5 or all")
                selected.extend(("http", "https", "socks4", "socks5") if token == "all" else [token])
    if not selected:
        raise ValueError("Select at least one proxy type")
    return list(dict.fromkeys(selected))


def _mobile_parser():
    import argparse
    parser = argparse.ArgumentParser(description="ProxyForge Mobile: select one or more proxy types; check all candidates by default and save plain IP:PORT files.")
    parser.add_argument("--type", "--types", action="append", nargs="+", metavar="TYPE", help="http https socks4 socks5 or all; spaces/commas/repeated flags supported")
    parser.add_argument("--count", type=int, default=0, help="Optional successful endpoint limit PER TYPE; default 0 checks all collected candidates")
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument("-o", "--output", type=Path, help="Single-type output filename (default: proxies.txt)")
    outputs.add_argument("--output-dir", type=Path, help="Output directory; multiple types use TYPE_proxies.txt")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--supersonic", action="store_true", help="Automatic HTTP-200 response mode; no extra settings required")
    modes.add_argument("--mode", choices=("verified", "supersonic", "tunnel"), help="Checking mode")
    parser.add_argument("--target", help="Legacy --mode tunnel destination HOST:PORT")
    parser.add_argument("--check-url", action="append", help="HTTP-200 test URL; repeat to balance targets (default: built-in tiny connectivity pages)")
    parser.add_argument("--fast-window", type=float, default=0.15)
    parser.add_argument("--slow-slots", type=int, help="Optional grace-slot override (default: automatic)")
    parser.add_argument("--tunnel-timeout", type=float, default=20)
    parser.add_argument("--tunnel-rate", type=float, default=0, help="Candidate starts/sec; 0 means no rate cap")
    parser.add_argument("--results-jsonl", type=Path, help="Optional supersonic outcomes including selected_type and inconclusive checks")
    parser.add_argument("--scrape-only", action="store_true", help="Return unverified candidates")
    parser.add_argument("--input", type=Path, action="append", default=[])
    parser.add_argument("--sources-file", type=Path, help="Custom JSON source registry, replacing embedded sources")
    parser.add_argument("--no-default-sources", action="store_true", help="Use only local --input files or --sources-file")
    parser.add_argument("--expanded", action="store_true")
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--fetch-concurrency", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=5, help="Verified-mode timeout; supersonic uses --tunnel-timeout")
    parser.add_argument("--source-timeout", type=float, default=12)
    parser.add_argument("--max-candidates", type=int, help="Candidate cap per type (default: 250000 Supersonic / 20000 verified)")
    parser.add_argument("--source-max-mb", type=float, default=12)
    parser.add_argument("--checks", type=int, default=1)
    parser.add_argument("--quorum", type=int)
    parser.add_argument("--rate", type=float, default=20, help="Verified-mode requests/sec; supersonic uses --tunnel-rate")
    parser.add_argument("--judge", action="append")
    parser.add_argument("--allow-http-judge", action="store_true")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--ipv6", action="store_true", help="Also include [IPv6]:PORT (default: IPv4 only)")
    parser.add_argument("--quiet", action="store_true", help="Hide progress; stdout always contains only proxy lines")
    parser.add_argument("--version", action="version", version="ProxyForge Mobile 1.4.0")
    return parser


def mobile_main(argv=None):
    import contextlib
    import shutil
    import sys
    import tempfile
    p = _mobile_parser()
    args = p.parse_args(argv)
    args.supersonic = args.supersonic or args.mode in ("supersonic", "tunnel")
    method = "tunnel" if args.mode == "tunnel" else "response"
    if args.target and method != "tunnel":
        p.error("--target requires --mode tunnel; use --check-url URL for HTTP-200 checking")
    if args.check_url and not args.supersonic:
        p.error("--check-url requires --supersonic or --mode supersonic")
    if args.supersonic and args.type is None:
        args.type = [["all"]]
    if args.type is None:
        if not sys.stdin.isatty():
            p.error("Use --type http|https|socks4|socks5|all when running noninteractively")
        print("ProxyForge Mobile\n1) HTTP\n2) HTTPS\n3) SOCKS4\n4) SOCKS5\n5) All", file=sys.stderr)
        print("Select proxy types (e.g. 1,4) [4]: ", end="", file=sys.stderr, flush=True)
        args.type = [[sys.stdin.readline().strip() or "4"]]
        if args.mode is None and not args.scrape_only:
            print("Checking mode: 1) Verified  2) Supersonic\nSelect mode [1]: ", end="", file=sys.stderr, flush=True)
            choice = sys.stdin.readline().strip().lower() or "1"
            if choice not in ("1", "2", "verified", "supersonic"):
                p.error("Choose verified or supersonic")
            args.supersonic = choice in ("2", "supersonic")
    try:
        proxy_types = _mobile_types(args.type)
    except ValueError as exc:
        p.error(str(exc))
    if len(proxy_types) > 1 and args.output:
        p.error("--output is for one proxy type; use --output-dir for multiple types")
    directory = args.output_dir or Path.cwd()
    paths = {kind: (args.output or directory / "proxies.txt") if len(proxy_types) == 1
             else directory / f"{kind}_proxies.txt" for kind in proxy_types}
    output_paths = {path.resolve() for path in paths.values()}
    uncertain_paths = {kind:path.with_name(path.stem + "_inconclusive.txt")
                       for kind,path in paths.items()} if args.supersonic else {}
    uncertain_outputs = {path.resolve() for path in uncertain_paths.values()}
    if output_paths.intersection(uncertain_outputs):
        p.error("Working output names must differ from automatic inconclusive output names")
    output_paths |= uncertain_outputs
    if args.supersonic and args.scrape_only:
        p.error("--supersonic cannot use --scrape-only")
    if args.results_jsonl and not args.supersonic:
        p.error("--results-jsonl requires --supersonic")
    protected = output_paths | {x.resolve() for x in args.input}
    if args.sources_file:
        protected.add(args.sources_file.resolve())
        if args.sources_file.resolve() in output_paths:
            p.error("Output files must differ from --sources-file")
    if args.results_jsonl and args.results_jsonl.resolve() in protected:
        p.error("--results-jsonl must differ from input/output/source paths")
    current = None
    counts = {kind: 0 for kind in proxy_types}
    printed = set()
    def progress(message):
        if not args.quiet:
            print(message, file=sys.stderr, flush=True)
    try:
        _number("source_max_mb", args.source_max_mb, minimum=0.001)
        _number("count", args.count, integer=True)
        registry = None
        if args.sources_file:
            registry = json.loads(args.sources_file.read_text(encoding="utf-8"))
        elif args.no_default_sources:
            registry = []
        # Snapshot any input that will also be an output before checking any
        # type. Later types must still read the original mixed input.
        with tempfile.TemporaryDirectory(prefix="proxyforge-input-") as tempdir, contextlib.ExitStack() as stack:
            inputs = []
            for index, path in enumerate(args.input):
                if path.resolve() in output_paths:
                    if path.stat().st_size > args.source_max_mb * 1000000:
                        raise ValueError(f"Input exceeds --source-max-mb: {path}")
                    snapshot = Path(tempdir) / f"input-{index}.txt"
                    shutil.copyfile(path, snapshot)
                    inputs.append(snapshot)
                else:
                    inputs.append(path)
            result_stream = None
            if args.results_jsonl:
                args.results_jsonl.parent.mkdir(parents=True, exist_ok=True)
                result_stream = stack.enter_context(args.results_jsonl.open("w", encoding="utf-8", buffering=1))
            # Run each selected protocol in its own thread/event loop. Divide
            # the supplied concurrency budgets across protocols rather than
            # multiplying them by the number of workers.
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import threading
            io_lock = threading.RLock()
            errors = []
            workers = len(proxy_types)
            def share_budget(total, minimum=1):
                return max(minimum, (total + workers - 1) // workers) if total is not None else None
            fetch_budget = share_budget(args.fetch_concurrency)
            # With automatic supersonic concurrency, use a bounded per-type
            # ceiling to avoid four independent governors saturating the host.
            check_budget = share_budget(args.concurrency) if args.concurrency is not None else (200 if workers > 1 else None)

            def run_type(kind):
                path = paths[kind]
                stream = None
                uncertain, passed = {}, set()
                completed = False
                progress(f"[{kind}] starting concurrently; saving to {path}; " + (f"limit {args.count}" if args.count else "no success-count limit"))
                def received(endpoint):
                    nonlocal stream
                    passed.add(endpoint)
                    uncertain.pop(endpoint, None)
                    if stream is None:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        stream = path.open("w", encoding="utf-8", buffering=1)
                    stream.write(endpoint + "\n")
                    stream.flush()
                    with io_lock:
                        counts[kind] += 1
                        if endpoint not in printed:
                            printed.add(endpoint)
                            print(endpoint, flush=True)
                def result(row):
                    if row['status'] == 'inconclusive' and row['endpoint'] not in passed:
                        uncertain[row['endpoint']] = None
                    if result_stream:
                        with io_lock:
                            result_stream.write(json.dumps(dict(row, selected_type=kind)) + "\n")
                            result_stream.flush()
                try:
                    get_proxies(
                        kind, count=args.count, check=not args.scrape_only, sources=registry,
                        expanded=args.expanded, input_files=inputs,
                        concurrency=check_budget,
                        fetch_concurrency=fetch_budget, timeout=args.timeout,
                        source_timeout=args.source_timeout, max_candidates=args.max_candidates,
                        max_source_bytes=int(args.source_max_mb * 1000000), rate=args.rate,
                        checks=args.checks, quorum=args.quorum, judges=args.judge,
                        allow_http_judge=args.allow_http_judge, allow_private=args.allow_private,
                        ipv4_only=not args.ipv6,
                        on_progress=lambda message: progress(f"[{kind}] {message}"), on_proxy=received,
                        supersonic=args.supersonic, target=args.target, fast_window=args.fast_window,
                        slow_slots=args.slow_slots, tunnel_timeout=args.tunnel_timeout,
                        tunnel_rate=args.tunnel_rate, on_result=result,
                        check_urls=args.check_url, supersonic_method=method,
                    )
                    completed = True
                    if stream is None:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("", encoding="utf-8")
                finally:
                    if stream:
                        stream.close()
                    if args.supersonic and (completed or uncertain):
                        uncertain_path = uncertain_paths[kind]
                        uncertain_path.parent.mkdir(parents=True, exist_ok=True)
                        uncertain_path.write_text(''.join(endpoint + '\n' for endpoint in uncertain), encoding='utf-8')
                        if uncertain:
                            progress(f"[{kind}] {len(uncertain)} unresolved endpoints saved to {uncertain_path}")
                progress(f"[{kind}] saved {counts[kind]} endpoints to {path}")

            progress(f"[parallel] Starting {workers} protocol workers; fetch concurrency per worker={fetch_budget}; check concurrency per worker={check_budget or 'auto'}")
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="proxyforge") as pool:
                futures = {pool.submit(run_type, kind): kind for kind in proxy_types}
                for future in as_completed(futures):
                    kind = futures[future]
                    try:
                        future.result()
                    except Exception as exc:
                        errors.append((kind, exc))
                        progress(f"[{kind}] ERROR: {exc}")
            if errors:
                progress(f"[parallel] {len(errors)} protocol worker(s) failed: " + ", ".join(kind for kind, _ in errors))
                return 1
        return 0 if any(counts.values()) else 2
    except KeyboardInterrupt:
        print("Interrupted; completed proxy lines are saved in the output files.", file=sys.stderr)
        return 130
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"ProxyForge Mobile{(' [' + current + ']') if current else ''}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(mobile_main())

