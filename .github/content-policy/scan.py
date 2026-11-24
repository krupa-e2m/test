#!/usr/bin/env python3
"""Content policy scanner.

Finds a restricted term in everything this repository publishes and reports
each location (file + line, PR field, comment, commit or release) to the
workflow log, the job summary, a commit status and Slack.

The term is assembled from character codes below, so no file in this folder
spells it out and the scanner never flags itself.

Commands
  pr                 PR events: lines the PR adds, file names, title,
                     description, branch name, commit messages and the whole
                     PR conversation. Sets the "content-policy" commit status.
  release            Release events: title, tag, notes, asset names and the
                     contents of every asset (zip files are opened).
  recent-releases    The newest releases (nightly; catches assets uploaded
                     after the release event fired).
  branch             Every file on a checked-out branch, plus the pushed
                     commit messages on push events.
  tree [DIR ...]     Local use: scan every file under DIR (default ".").
  text STRING        Local use: check one string.

Standard library only, so the workflow needs no install step.
"""

from __future__ import annotations

import hashlib
import html
import io
import json
import os
import re
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

# --- The term ----------------------------------------------------------------
# Letter, digit, letter, plus spelled-out forms of the last two. Built from
# character codes so this file never contains the term itself.
_A, _B, _C = chr(101), chr(50), chr(109)
_B_WORD, _C_WORD = "two", chr(101) + chr(109)

# Characters people put between the letters.
_SEP = r"[\s._\-/\\|*+~:,'\"`]"

# Compact form, matched anywhere - including inside identifiers.
_COMPACT = re.compile(_A + _B + _C, re.I)
# Compact form that must start a word. Used where random letter soup is
# common (minified/lock files, very long lines), to avoid chance matches.
_COMPACT_WORD = re.compile(r"(?<![a-z0-9])" + _A + _B + _C, re.I)
# Separated and spelled-out forms. Both ends must be word boundaries, or
# ordinary phrases would match ("size 2 minutes", "the two men").
_SPACED = re.compile(
    rf"(?<![a-z0-9]){_A}{_SEP}{{0,3}}(?:{_B}|{_B_WORD}){_SEP}{{0,3}}(?:{_C}|{_C_WORD})(?![a-z0-9])",
    re.I,
)

# Long base64-looking runs are blanked before the compact check: data URIs
# and embedded fonts would otherwise produce chance matches.
_BASE64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

# Characters that render as nothing; removed so they can't split the term.
_INVISIBLE = dict.fromkeys(
    map(ord, "­͏؜ᅟᅠ᠎​‌‍‎‏"
             "‪‫‬‭‮⁠⁡⁢⁣⁤"
             "⁦⁧⁨⁩﻿")
)
# Cyrillic/Greek letters that look like the Latin ones. Full-width, math and
# superscript forms are already folded by NFKC.
_LOOKALIKES = str.maketrans("еЕεΕмМΜ", "eEeEmMM")

# \x45, E, \u{0045}, %45 - decoded so escaped spellings are caught too.
_ESCAPE = re.compile(r"\\x([0-9a-f]{2})|\\u\{?([0-9a-f]{4})\}?|%([0-9a-f]{2})", re.I)

# Files full of generated tokens, where only word-start matches count.
_NOISY_FILE = re.compile(
    r"(\.min\.(js|css)|\.map|\.lock|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|composer\.lock)$", re.I
)
_NOISY_LINE_LENGTH = 500

# Commit trailers carry author identities, which are out of scope.
_IDENTITY_TRAILER = re.compile(r"^\s*[\w-]+-by:\s.*<[^>]*@[^>]*>\s*$", re.I)

# (location, value) of hits skipped as random values since the last report().
IGNORED: list[tuple[str, str]] = []

MAX_BYTES = 100 * 1024 * 1024
MAX_ZIP_DEPTH = 2
STATUS_CONTEXT = "content-policy"
SLACK_MAX_ITEMS = 20

HERE = Path(__file__).resolve().parent
ALLOWLIST = HERE / "allowlist.txt"
SERVER = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
REPO = os.environ.get("GITHUB_REPOSITORY", "")


# Random values (salts, keys, build IDs) can contain the compact form by
# chance. A hit is ignored only when it sits inside a quoted or assigned
# value that has no spaces, is 16+ characters, switches between lower/upper/
# digit/symbol on most characters, is mostly not word-like, and the term is
# not at the value's edge, next to a separator, or a camelCase segment.
_QUOTED_VALUE = re.compile(r"""(['"`])([^'"`\s]{16,})\1""")
_ASSIGNED_VALUE = re.compile(r"""[=:]\s*([^\s'"`;,]{16,})""")
_WORD_RUN = re.compile(r"[a-z]{6,}")
_WORDISH = re.compile(r"[A-Z]?[a-z]{2,}")      # "Sync", "Api", "ab"
_MAX_WORDISH = 0.4
_VALUE_SEPARATORS = "_-./"
_MIN_CLASS_CHANGES = 0.5


# --- Matching -----------------------------------------------------------------

def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_LOOKALIKES).translate(_INVISIBLE)


def _unescape(text: str) -> str:
    text = html.unescape(text)
    return _ESCAPE.sub(lambda m: chr(int(next(g for g in m.groups() if g), 16)), text)


def _char_class(char: str) -> str:
    return "l" if char.islower() else "u" if char.isupper() else "d" if char.isdigit() else "s"


def random_value(text: str, hit: re.Match) -> str | None:
    """The value around HIT if it looks like a random string, else None."""
    for pattern in (_QUOTED_VALUE, _ASSIGNED_VALUE):
        for m in pattern.finditer(text):
            start, end = m.span(m.lastindex)
            if not start <= hit.start() < hit.end() <= end:
                continue
            value = m.group(m.lastindex)
            before = text[hit.start() - 1] if hit.start() > start else ""
            after = text[hit.end()] if hit.end() < end else ""
            if not before or not after or before in _VALUE_SEPARATORS or after in _VALUE_SEPARATORS:
                return None
            if _camel_segment(hit.group(), before, after):
                return None
            classes = [_char_class(c) for c in value]
            changes = sum(a != b for a, b in zip(classes, classes[1:])) / (len(value) - 1)
            wordish = sum(len(w) for w in _WORDISH.findall(value)) / len(value)
            if changes < _MIN_CLASS_CHANGES or wordish > _MAX_WORDISH or _WORD_RUN.search(value):
                return None
            return value
    return None


def _camel_segment(term: str, before: str, after: str) -> bool:
    """True when the term reads as its own camelCase part, as in "getXYZData"."""
    if term.isupper():
        return not before.isupper() and after.isupper()
    if term[0].isupper() and term[-1].islower():
        return before.islower() and after.isupper()
    return False


def match(text: str | None, noisy: bool = False, ignored: list[str] | None = None) -> str | None:
    """Return a snippet around the term if TEXT contains it, else None.

    Hits inside random-looking values are skipped and, when IGNORED is
    given, the values are added to it.
    """
    if not text:
        return None
    seen = set()
    for variant in (normalize(text), normalize(_unescape(text))):
        if variant in seen:
            continue
        seen.add(variant)
        strict = noisy or len(variant) > _NOISY_LINE_LENGTH
        masked = _BASE64.sub(lambda m: " " * len(m.group()), variant)
        found = None
        for candidate in (_COMPACT_WORD if strict else _COMPACT).finditer(masked):
            value = random_value(masked, candidate)
            if value is None:
                found = candidate
                break
            if ignored is not None and value not in ignored:
                ignored.append(value)
        found = found or _SPACED.search(variant)
        if found:
            snippet = variant[max(0, found.start() - 40):found.end() + 40].strip()
            return " ".join(snippet.split())
    return None


# --- Findings -----------------------------------------------------------------

@dataclass
class Finding:
    where: str          # file path, "PR title", "commit abc1234", ...
    kind: str           # what was scanned: code, file name, PR title, ...
    text: str           # snippet around the match
    line: int | None = None
    url: str = ""
    path: str = ""      # repo-relative path, for annotations
    who: str = ""       # GitHub login of the comment/review author, if any

    def location(self) -> str:
        return f"{self.where}:{self.line}" if self.line else self.where

    def key(self) -> str:
        return f"{self.where}:{self.line or 0}:{self.text}"


def scan_text(where: str, kind: str, text: str | None, url: str = "", numbered: bool = True) -> list[Finding]:
    findings = []
    for no, line in enumerate((text or "").splitlines(), 1):
        hit = match(line)
        if hit:
            findings.append(Finding(where, kind, hit, no if numbered else None, url))
    return findings


def scan_message(sha: str, message: str, url: str = "") -> list[Finding]:
    findings = []
    for no, line in enumerate((message or "").splitlines(), 1):
        if _IDENTITY_TRAILER.match(line):
            continue
        hit = match(line)
        if hit:
            findings.append(Finding(f"commit {sha[:7]}", "commit message", hit, no, url))
    return findings


def apply_allowlist(findings: list[Finding]) -> list[Finding]:
    if not ALLOWLIST.exists():
        return findings
    rules = [
        re.compile(line.strip())
        for line in ALLOWLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return [f for f in findings if not any(rule.search(f.key()) for rule in rules)]


# --- File contents ------------------------------------------------------------

def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff"))


def decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def scan_content(name: str, data: bytes, only_lines: set[int] | None = None, depth: int = 0):
    """Yield (where, line, snippet) for every hit in DATA.

    ONLY_LINES limits a text file to those line numbers (the lines a PR
    added). Zip-based files (zip, docx, xlsx, pptx, odt...) are opened and
    every entry is scanned; other binaries are scanned for embedded text.
    """
    if len(data) > MAX_BYTES:
        print(f"::warning::Skipped {name}: larger than {MAX_BYTES // 1024 // 1024} MB")
        return
    if data[:4] == b"PK\x03\x04":
        yield from _scan_zip(name, data, depth)
        return
    if is_binary(data):
        for hit in _binary_hits(data):
            yield name, None, hit
        return
    noisy = bool(_NOISY_FILE.search(name))
    for no, line in enumerate(decode(data).splitlines(), 1):
        if only_lines is not None and no not in only_lines:
            continue
        ignored = []
        hit = match(line, noisy, ignored)
        if hit:
            yield name, no, hit
        IGNORED.extend((f"{name}:{no}", value) for value in ignored)


def _scan_zip(name: str, data: bytes, depth: int):
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        for hit in _binary_hits(data):
            yield name, None, hit
        return
    entries = archive.namelist()
    office = "[Content_Types].xml" in entries or "mimetype" in entries
    for info in archive.infolist():
        inner = f"{name}!{info.filename}"
        hit = match(info.filename)
        if hit:
            yield inner, None, f"(file name) {hit}"
        if info.is_dir() or info.file_size > MAX_BYTES or depth >= MAX_ZIP_DEPTH:
            continue
        try:
            blob = archive.read(info)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError):
            continue  # encrypted or unsupported compression
        if office and info.filename.endswith(".xml"):
            # Word & co. split text across XML runs; drop the tags so the
            # pieces join up again, one paragraph per line.
            blob = re.sub(rb"</(?:w|a|text):p>|<(?:w:)?br\s*/?>", b"\n", blob)
            blob = re.sub(rb"<[^>]+>", b"", blob)
        yield from scan_content(inner, blob, depth=depth + 1)


_ASCII_RUN = re.compile(rb"[\x20-\x7e]{8,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")


def _binary_hits(data: bytes) -> list[str]:
    """Text embedded in binaries: image metadata, fonts, PDFs, executables."""
    chunks = [data]
    if data.startswith(b"%PDF"):
        chunks += _pdf_streams(data)
    if data.startswith(b"\x89PNG"):
        chunks += _png_text(data)
    hits = []
    for chunk in chunks:
        runs = [m.group().decode("ascii") for m in _ASCII_RUN.finditer(chunk)]
        runs += [m.group().decode("utf-16-le") for m in _UTF16_RUN.finditer(chunk)]
        for run in runs:
            hit = match(run)
            if hit and hit not in hits:
                hits.append(hit)
    return hits


def _pdf_streams(data: bytes) -> list[bytes]:
    out = []
    for start in re.finditer(rb"stream\r?\n", data):
        end = data.find(b"endstream", start.end())
        if end < 0:
            break
        try:
            out.append(zlib.decompressobj().decompress(data[start.end():end]))
        except zlib.error:
            pass
    return out


def _png_text(data: bytes) -> list[bytes]:
    out, pos = [], 8
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        try:
            if kind == b"zTXt":
                keyword, _, rest = body.partition(b"\0")
                out.append(keyword + b" " + zlib.decompress(rest[1:]))
            elif kind == b"iTXt":
                keyword, _, rest = body.partition(b"\0")
                compressed, rest = rest[:1] == b"\1", rest[2:]
                _, _, rest = rest.partition(b"\0")      # language tag
                _, _, text = rest.partition(b"\0")      # translated keyword
                out.append(keyword + b" " + (zlib.decompress(text) if compressed else text))
        except zlib.error:
            pass
        pos += 12 + length
    return out


# --- Git ----------------------------------------------------------------------

def git(repo: Path, *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.quotePath=false", *args],
        capture_output=True, check=True,
    )
    return result.stdout if binary else result.stdout.decode("utf-8", "replace")


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(repo: Path, base: str, head: str) -> dict[str, set[int]]:
    """Line numbers (in the new file) of every line the PR adds or changes."""
    diff = git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", "-M", "--diff-filter=ACMR", f"{base}...{head}")
    result: dict[str, set[int]] = {}
    path, line = None, 0
    for row in diff.splitlines():
        if row.startswith("+++ "):
            path = row[6:] if row.startswith("+++ b/") else None
            if path is not None:
                result.setdefault(path, set())
        elif row.startswith("@@"):
            found = _HUNK.match(row)
            line = int(found.group(1)) if found else 0
        elif row.startswith("+") and path is not None:
            result[path].add(line)
            line += 1
    return result


def changed_paths(repo: Path, base: str, head: str) -> list[str]:
    parts = git(repo, "diff", "--name-status", "-z", "-M", "--diff-filter=ACMR", f"{base}...{head}").split("\0")
    paths, i = [], 0
    while i < len(parts) and parts[i]:
        if parts[i][0] in "RC":          # rename/copy: status, old, new
            paths.append(parts[i + 2])
            i += 3
        else:
            paths.append(parts[i + 1])
            i += 2
    return paths


def blob_url(sha: str, path: str, line: int | None = None) -> str:
    if not REPO:
        return ""
    return f"{SERVER}/{REPO}/blob/{sha}/{urllib.parse.quote(path)}" + (f"#L{line}" if line else "")


def commit_url(sha: str) -> str:
    return f"{SERVER}/{REPO}/commit/{sha}" if REPO else ""


def scan_pr_code(repo: Path, base: str, head: str) -> list[Finding]:
    findings = []
    lines = added_lines(repo, base, head)
    for path in changed_paths(repo, base, head):
        hit = match(path)
        if hit:
            findings.append(Finding(path, "file name", hit, url=blob_url(head, path), path=path))
        try:
            data = git(repo, "cat-file", "blob", f"{head}:{path}", binary=True)
        except subprocess.CalledProcessError:
            continue  # submodule or vanished path
        whole_file = is_binary(data) or data[:4] == b"PK\x03\x04"
        for where, no, snippet in scan_content(path, data, None if whole_file else lines.get(path, set())):
            kind = "code" if where == path and no else "binary content"
            findings.append(Finding(where, kind, snippet, no, blob_url(head, path, no if where == path else None), path))
    return findings


def scan_commits(repo: Path, revisions: str) -> list[Finding]:
    findings = []
    for entry in git(repo, "log", "--format=%H%x00%B%x1e", revisions).split("\x1e"):
        sha, _, message = entry.strip("\n").partition("\x00")
        if sha:
            findings += scan_message(sha, message, commit_url(sha))
    return findings


def tree_files(root: Path) -> list[Path]:
    try:
        # Tracked plus new (untracked, not ignored) files.
        listing = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        return [root / p for p in listing.split("\0") if p and (root / p).is_file()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        skip = {".git", "node_modules", "__pycache__"}
        return [p for p in root.rglob("*") if p.is_file() and not skip & set(p.relative_to(root).parts)]


def scan_tree(root: Path, sha: str = "") -> list[Finding]:
    findings = []
    for file in tree_files(root):
        rel = file.relative_to(root).as_posix()
        hit = match(rel)
        if hit:
            findings.append(Finding(rel, "file name", hit, url=blob_url(sha, rel) if sha else "", path=rel))
        if file.stat().st_size > MAX_BYTES:
            print(f"::warning::Skipped {rel}: larger than {MAX_BYTES // 1024 // 1024} MB")
            continue
        for where, no, snippet in scan_content(rel, file.read_bytes()):
            kind = "code" if where == rel and no else "binary content"
            url = blob_url(sha, rel, no if where == rel else None) if sha else ""
            findings.append(Finding(where, kind, snippet, no, url, rel))
    return findings


# --- GitHub API -----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN", "")
        self.api = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    def _request(self, url: str, method: str = "GET", body=None, accept: str = "application/vnd.github+json"):
        if not url.startswith("http"):
            url = f"{self.api}/repos/{REPO}/{url.lstrip('/')}"
        request = urllib.request.Request(
            url,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "content-policy",
            },
        )
        return request

    def json(self, path: str, method: str = "GET", body=None):
        with urllib.request.urlopen(self._request(path, method, body), timeout=60) as response:
            data = response.read()
        return json.loads(data) if data else None

    def paginate(self, path: str) -> list:
        url = self._request(path).full_url
        url += ("&" if "?" in url else "?") + "per_page=100"
        items = []
        while url:
            with urllib.request.urlopen(self._request(url), timeout=60) as response:
                items += json.loads(response.read())
                found = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link", ""))
            url = found.group(1) if found else None
        return items

    def download(self, asset_api_url: str) -> bytes:
        # Assets redirect to storage that rejects our Authorization header,
        # so follow the redirect by hand without it.
        request = self._request(asset_api_url, accept="application/octet-stream")
        try:
            with urllib.request.build_opener(_NoRedirect).open(request, timeout=300) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise
            location = error.headers["Location"]
        with urllib.request.urlopen(urllib.request.Request(location, headers={"User-Agent": "content-policy"}), timeout=300) as response:
            return response.read()

    def status(self, sha: str) -> dict | None:
        try:
            for status in self.json(f"commits/{sha}/statuses") or []:
                if status.get("context") == STATUS_CONTEXT:
                    return status    # newest first
        except (urllib.error.URLError, OSError):
            pass
        return None

    def set_status(self, sha: str, findings: list[Finding], fingerprint: str) -> bool:
        description = (
            f"{len(findings)} restricted-term finding(s) [{fingerprint}]" if findings else "No restricted term found"
        )
        body = {"state": "failure" if findings else "success", "context": STATUS_CONTEXT, "description": description[:140]}
        if run_url():
            body["target_url"] = run_url()
        try:
            self.json(f"statuses/{sha}", "POST", body)
            return True
        except (urllib.error.URLError, OSError) as error:
            print(f"::warning::Could not set the {STATUS_CONTEXT} commit status: {error}")
            return False


def scan_conversation(gh: GitHub, number: int) -> list[Finding]:
    def login(item):
        return (item.get("user") or {}).get("login", "ghost")

    def scan_item(item, where, kind):
        found = scan_text(where, kind, item.get("body"), item["html_url"])
        for f in found:
            f.who = login(item)
        return found

    findings = []
    for comment in gh.paginate(f"issues/{number}/comments"):
        findings += scan_item(comment, f"comment by {login(comment)}", "PR comment")
    for comment in gh.paginate(f"pulls/{number}/comments"):
        where = f"review comment by {login(comment)} on {comment.get('path', '')}"
        findings += scan_item(comment, where, "review comment")
    for review in gh.paginate(f"pulls/{number}/reviews"):
        findings += scan_item(review, f"review by {login(review)}", "review")
    return findings


def scan_release(gh: GitHub, release: dict) -> list[Finding]:
    tag, url = release.get("tag_name", ""), release.get("html_url", "")
    findings = scan_text(f"release {tag} title", "release title", release.get("name"), url, numbered=False)
    findings += scan_text(f"release {tag} tag", "release tag", tag, url, numbered=False)
    findings += scan_text(f"release {tag} notes", "release notes", release.get("body"), url)
    for asset in release.get("assets", []):
        download_url = asset.get("browser_download_url", "")
        findings += scan_text(f"release {tag} asset", "release asset name", asset["name"], download_url, numbered=False)
        if asset.get("size", 0) > MAX_BYTES:
            print(f"::warning::Skipped asset {asset['name']}: larger than {MAX_BYTES // 1024 // 1024} MB")
            continue
        data = gh.download(asset["url"])
        for where, no, snippet in scan_content(asset["name"], data):
            findings.append(Finding(f"release {tag} asset {where}", "release asset content", snippet, no, download_url))
    return findings


# --- Reporting ------------------------------------------------------------------

def run_url() -> str:
    run_id = os.environ.get("GITHUB_RUN_ID")
    return f"{SERVER}/{REPO}/actions/runs/{run_id}" if run_id and REPO else ""


def fingerprint(findings: list[Finding]) -> str:
    return hashlib.sha1("\n".join(sorted(f.key() for f in findings)).encode()).hexdigest()[:10]


def _annotation(value: str, prop: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return value.replace(":", "%3A").replace(",", "%2C") if prop else value


def report(subject: str, findings: list[Finding]) -> None:
    if not findings:
        print(f"Content policy: clean - {subject}")
    else:
        print(f"Content policy: {len(findings)} finding(s) - {subject}")
        for f in findings:
            print(f"  [{f.kind}] {f.location()}  {f.text}" + (f"\n      {f.url}" if f.url else ""))
            if os.environ.get("GITHUB_ACTIONS"):
                props = "title=Restricted term"
                if f.path:
                    line = f"line={f.line}," if f.line and f.where == f.path else ""
                    props = f"file={_annotation(f.path, True)},{line}{props}"
                print(f"::error {props}::{_annotation(f.kind + ': ' + f.text)}")
    ignored = IGNORED[:]
    IGNORED.clear()
    for where, value in ignored:
        print(f"  [ignored - looks random] {where}  {value}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    with open(summary, "a", encoding="utf-8") as out:
        if not findings:
            out.write(f"### Content policy: clean\n{subject}\n\n")
        else:
            out.write(f"### Content policy: {len(findings)} finding(s)\n{subject}\n\n")
            out.write("This is a white-label product. Remove these before merging.\n\n")
            out.write("| Where | What | Text |\n|---|---|---|\n")
            for f in findings:
                where = f"[{f.location()}]({f.url})" if f.url else f.location()
                text = f.text.replace("|", "\\|").replace("`", "'")
                out.write(f"| {where.replace('|', chr(92) + '|')} | {f.kind} | `{text}` |\n")
            out.write("\n")
        # Below the findings: they matter less and don't fail the check.
        if ignored:
            out.write(f"#### Ignored: {len(ignored)} random string(s)\n\n")
            out.write("These look like random strings (salts, keys, hashes), so they're not counted "
                      "as findings. If any of them is a real mention, remove it anyway.\n\n")
            out.write("| Where | Value |\n|---|---|\n")
            for where, value in ignored:
                cell = value.replace("`", "'").replace("|", chr(92) + "|")
                out.write(f"| {where.replace('|', chr(92) + '|')} | `{cell}` |\n")
            out.write("\n")


def _slack(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _slack_link(url: str, label: str) -> str:
    return f"<{url}|{_slack(label)}>" if url else _slack(label)


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


# SLACK_USER_MAP (a repository Actions variable, not a file) maps GitHub
# logins to Slack member IDs: {"octocat": "U012AB3CD"}. It stays out of the
# repo because logins can contain the term themselves.
_SLACK_MEMBER_ID = re.compile(r"^[UW][A-Z0-9]{6,}$")


def slack_users() -> dict[str, str]:
    raw = os.environ.get("SLACK_USER_MAP", "").strip()
    if not raw:
        return {}
    try:
        users = json.loads(raw)
    except ValueError as error:
        print(f"::warning::SLACK_USER_MAP is not valid JSON ({error}) - nobody is mentioned.")
        return {}
    if not isinstance(users, dict):
        print("::warning::SLACK_USER_MAP must be a JSON object - nobody is mentioned.")
        return {}
    return {str(k).lower(): str(v).strip().lstrip("@") for k, v in users.items() if v}


def mention(login: str, users: dict[str, str]) -> str:
    """Slack text for a GitHub login: a real @-mention when it's mapped to a member ID."""
    slack = users.get(login.lower())
    if not slack:
        return f"*{_slack(login)}*"
    if _SLACK_MEMBER_ID.match(slack):
        return f"<@{slack}> ({_slack(login)})"
    # Webhooks can't resolve names, so a name is shown but notifies nobody.
    print(f"::warning::SLACK_USER_MAP: '{slack}' (for {login}) is not a Slack member ID - "
          "shown as text, nobody is notified. Use the member ID (starts with U).")
    return f"*@{_slack(slack)}* ({_slack(login)})"


def slack_alert(subject: str, url: str, findings: list[Finding], actor: str = "") -> dict:
    users = slack_users()
    intro = f"*{_slack_link(url, subject)}*\n"
    intro += (f"By {mention(actor, users)} · " if actor else "") + f"{len(findings)} location(s)"
    commenters = sorted({f.who for f in findings if f.who and f.who.lower() != actor.lower()}, key=str.lower)
    if commenters:
        intro += "\nFlagged comments by " + ", ".join(mention(who, users) for who in commenters)
    rows = []
    for f in findings[:SLACK_MAX_ITEMS]:
        snippet = _slack(f.text[:150]).replace("`", "'")
        rows.append(f"• {_slack_link(f.url, f.location())}  _{f.kind}_\n      `{snippet}`")
    if len(findings) > SLACK_MAX_ITEMS:
        rows.append(f"…and {len(findings) - SLACK_MAX_ITEMS} more: {_slack_link(run_url(), 'full list')}")

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": ":no_entry: Restricted term found", "emoji": True}},
        _section(intro),
    ]
    chunk = ""
    for row in rows:
        if len(chunk) + len(row) > 2900:     # Slack caps a section at 3000 chars
            blocks.append(_section(chunk))
            chunk = ""
        chunk += row + "\n"
    if chunk:
        blocks.append(_section(chunk))
    footer = "Remove it and the check re-runs automatically."
    if run_url():
        footer += f" · {_slack_link(run_url(), 'Workflow run')}"
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": footer}]})
    return {"text": f"Restricted term found: {subject}", "blocks": blocks}


def slack_resolved(subject: str, url: str, actor: str = "") -> dict:
    text = f":white_check_mark: *{_slack_link(url, subject)}* is clean now - the restricted term was removed."
    if actor:
        text += f"\nThanks {mention(actor, slack_users())}"
    return {"text": f"Resolved: {subject}", "blocks": [_section(text)]}


def post_slack(payload: dict) -> None:
    if os.environ.get("CONTENT_POLICY_SLACK_DRY_RUN"):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    hook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not hook:
        print("::warning::SLACK_WEBHOOK_URL is not set - skipping the Slack notification.")
        return
    request = urllib.request.Request(hook, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request, timeout=30).read()
    except (urllib.error.URLError, OSError) as error:
        print(f"::warning::Slack notification failed: {error}")


# --- Commands -------------------------------------------------------------------

def _payload() -> dict:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_base(repo: Path, sha: str, ref: str) -> str:
    try:
        git(repo, "cat-file", "-e", f"{sha}^{{commit}}")
        return sha
    except subprocess.CalledProcessError:
        return f"origin/{ref}"


def scan_pr(gh: GitHub, pr: dict, repo: Path) -> list[Finding]:
    url = pr.get("html_url", "")
    findings = scan_text("PR title", "PR title", pr.get("title"), url, numbered=False)
    findings += scan_text("PR description", "PR description", pr.get("body"), url)
    findings += scan_text("branch name", "branch name", pr["head"]["ref"], url, numbered=False)
    base = _resolve_base(repo, pr["base"]["sha"], pr["base"]["ref"])
    head = pr["head"]["sha"]
    findings += scan_pr_code(repo, base, head)
    findings += scan_commits(repo, f"{base}..{head}")
    if gh.token:
        findings += scan_conversation(gh, pr["number"])
    return findings


def cmd_pr() -> int:
    payload, gh = _payload(), GitHub()
    number = (payload.get("pull_request") or payload.get("issue") or {}).get("number")
    pr = gh.json(f"pulls/{number}") if gh.token else payload["pull_request"]
    repo = Path(os.environ.get("TARGET_DIR", "."))

    findings = apply_allowlist(scan_pr(gh, pr, repo))
    subject = f"PR #{pr['number']}: {pr['title']}"
    report(subject, findings)
    author = (pr.get("user") or {}).get("login", "")

    if not gh.token:
        if findings:
            post_slack(slack_alert(subject, pr.get("html_url", ""), findings, author))
        return 1 if findings else 0

    # Only alert when the findings change, so editing a description or adding
    # comments doesn't repeat the same Slack message.
    head = pr["head"]["sha"]
    current = fingerprint(findings)
    previous = gh.status(head) or (gh.status(payload["before"]) if payload.get("before") else None)
    status_set = gh.set_status(head, findings, current)
    was_failing = bool(previous and previous.get("state") == "failure")
    if findings and not (was_failing and current in previous.get("description", "")):
        post_slack(slack_alert(subject, pr["html_url"], findings, author))
    elif findings:
        print("Same findings as the last alert - not notifying Slack again.")
    elif was_failing:
        post_slack(slack_resolved(subject, pr["html_url"], author))
    # The "content-policy" status is the one gate on the PR. Each event type
    # (PR update, comment, review) keeps its own job entry, so failing the job
    # too would leave stale red entries after the PR is fixed. Only fail the
    # job when the status couldn't be set.
    return 0 if status_set else (1 if findings else 0)


def _run_releases(gh: GitHub, releases: list[dict]) -> int:
    failed = 0
    for release in releases:
        findings = apply_allowlist(scan_release(gh, release))
        subject = f"Release {release.get('tag_name', '')}" + (" (draft)" if release.get("draft") else "")
        report(subject, findings)
        if findings:
            actor = (release.get("author") or {}).get("login", "")
            post_slack(slack_alert(subject, release.get("html_url", ""), findings, actor))
            failed = 1
    return failed


def cmd_release() -> int:
    gh = GitHub()
    release = _payload()["release"]
    if gh.token:
        release = gh.json(f"releases/{release['id']}")   # fresh asset list
    return _run_releases(gh, [release])


def cmd_recent_releases() -> int:
    gh = GitHub()
    count = int(os.environ.get("RECENT_RELEASES", "10"))
    return _run_releases(gh, gh.json(f"releases?per_page={count}") or [])


def cmd_branch() -> int:
    repo = Path(os.environ.get("TARGET_DIR", "."))
    label = os.environ.get("TARGET_REF") or git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    sha = git(repo, "rev-parse", "HEAD").strip()
    event = os.environ.get("GITHUB_EVENT_NAME", "")

    findings = scan_tree(repo, sha)
    actor = ""
    if event in ("push", "workflow_dispatch"):
        payload = _payload()
        # The person who pushed, or who started the manual run. Nightly: nobody.
        actor = (payload.get("sender") or {}).get("login") or (payload.get("pusher") or {}).get("name", "")
    if event == "push":
        for commit in payload.get("commits", []):
            findings += scan_message(commit["id"], commit.get("message", ""), commit.get("url", ""))
    findings = apply_allowlist(findings)

    suffix = {"push": " (after push)", "schedule": " (nightly scan)", "workflow_dispatch": " (manual scan)"}
    subject = f"Branch {label}{suffix.get(event, '')}"
    report(subject, findings)
    if findings:
        url = f"{SERVER}/{REPO}/tree/{urllib.parse.quote(label)}" if REPO else ""
        post_slack(slack_alert(subject, url, findings, actor))
    return 1 if findings else 0


def cmd_tree(dirs: list[str]) -> int:
    failed = 0
    for directory in dirs or ["."]:
        path = Path(directory)
        if not path.exists():
            print(f"::error::{directory}: no such file or folder")
            failed = 1
            continue
        if path.is_file():
            findings = [f for f in scan_tree(path.parent) if f.path == path.name]
        else:
            findings = scan_tree(path)
        findings = apply_allowlist(findings)
        report(directory, findings)
        failed |= bool(findings)
    return failed


def cmd_text(text: str) -> int:
    hit = match(text)
    print(f"match: {hit}" if hit else "no match")
    return 1 if hit else 0


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    command, args = (argv[0], argv[1:]) if argv else ("", [])
    commands = {
        "pr": cmd_pr,
        "release": cmd_release,
        "recent-releases": cmd_recent_releases,
        "branch": cmd_branch,
    }
    if command in commands:
        return commands[command]()
    if command == "tree":
        return cmd_tree(args)
    if command == "text" and args:
        return cmd_text(" ".join(args))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
