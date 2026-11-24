"""Tests for scan.py.  Run:  python .github/content-policy/tests/test_scan.py

Every string containing the term is built at runtime from character codes,
so this file passes its own scan.
"""

import io
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCANNER = HERE.parent / "scan.py"
sys.path.insert(0, str(HERE.parent))
sys.dont_write_bytecode = True
import scan  # noqa: E402

C1, C2, C3 = chr(101), chr(50), chr(109)
T = "".join([C1, C2, C3])  # lower-case compact form
U = T.upper()


def joined(sep, first=C1, mid=C2, last=C3):
    return first + sep + mid + sep + last


SHOULD_MATCH = {
    "upper": U,
    "lower": T,
    "mixed": U[0] + C2 + C3,
    "in a sentence": f"Built by {U} Solutions",
    "inside identifier": f"my{U}Helper",
    "domain": f"dev@{T}solutions.com",
    "hyphen": joined("-"),
    "underscore": joined("_"),
    "dot": joined("."),
    "space": joined(" "),
    "slash": joined(" / "),
    "spelled": joined(" ", mid="two"),
    "spelled title case": joined("-", first="E", mid="Two", last="M"),
    "spelled joined": joined("", mid="two"),
    "spelled em": joined(" ", mid="two", last=C1 + C3),
    "full-width": "".join(chr(ord(c) + 0xFEE0) for c in U),
    "cyrillic e": "е" + C2 + C3,
    "superscript two": U[0] + "²" + U[2],
    "zero-width inside": U[0] + "​" + U[1:],
    "html entities": "".join(f"&#{ord(c)};" for c in U),
    "hex escapes": "".join("\\x%02x" % ord(c) for c in U),
    "url encoded": "".join("%%%02X" % ord(c) for c in U),
}

SHOULD_NOT_MATCH = [
    "size 2 minutes",
    "the two men",
    "1" + C1 + "-2 m",            # scientific notation: 0.01 m
    "phase 2 milestone",
    C1 + "2" + C1 + " tests",
    C3 + C1 + C2,
    "color: #9f2e7d",
    "a" * 40 + T + "b" * 40,     # inside a base64-like run
    "",
]


class MatchTests(unittest.TestCase):
    def test_variants_match(self):
        for name, text in SHOULD_MATCH.items():
            with self.subTest(name):
                self.assertIsNotNone(scan.match(text), repr(text))

    def test_ordinary_text_does_not_match(self):
        for text in SHOULD_NOT_MATCH:
            with self.subTest(text):
                self.assertIsNone(scan.match(text), repr(text))

    def test_noisy_files_need_word_start(self):
        self.assertIsNone(scan.match("var x='ab" + T + "q';", noisy=True))
        self.assertIsNotNone(scan.match("/* by " + U + " */", noisy=True))

    def test_identity_trailers_are_skipped(self):
        message = f"Fix footer\n\nSigned-off-by: Dev <dev@{T}solutions.com>"
        self.assertEqual(scan.scan_message("abc1234", message), [])
        self.assertEqual(len(scan.scan_message("abc1234", f"Add {U} logo")), 1)


class ContentTests(unittest.TestCase):
    def test_text_file_line_numbers(self):
        data = f"one\ntwo\nby {U}\n".encode()
        self.assertEqual([(w, n) for w, n, _ in scan.scan_content("a.php", data)], [("a.php", 3)])

    def test_only_lines_filter(self):
        data = f"{U}\nok\n{U}\n".encode()
        self.assertEqual([n for _, n, _ in scan.scan_content("a.php", data, {3})], [3])

    def test_zip_entries_and_names(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("plugin/readme.txt", f"a\nb\nMade by {U}\n")
            z.writestr(f"plugin/{T}-logo.svg", "<svg/>")
        hits = list(scan.scan_content("plugin.zip", buf.getvalue()))
        self.assertIn(("plugin.zip!plugin/readme.txt", 3), [(w, n) for w, n, _ in hits])
        self.assertTrue(any("(file name)" in s for _, _, s in hits))

    def test_docx_text_split_across_runs(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml",
                       f"<w:p><w:r><w:t>Made by {U[:2]}</w:t></w:r><w:r><w:t>{U[2:]}</w:t></w:r></w:p>")
        self.assertEqual(len(list(scan.scan_content("guide.docx", buf.getvalue()))), 1)

    def test_png_compressed_metadata(self):
        text = b"Author\0\0" + zlib.compress(f"Studio {U}".encode())
        chunk = len(text).to_bytes(4, "big") + b"zTXt" + text + b"\0\0\0\0"
        self.assertEqual(len(list(scan.scan_content("a.png", b"\x89PNG\r\n\x1a\n" + chunk))), 1)

    def test_binary_embedded_text(self):
        data = b"\x00\x01" * 50 + f"Copyright {U} Solutions".encode() + b"\x00" * 10
        self.assertEqual(len(list(scan.scan_content("font.woff", data))), 1)

    def test_random_binary_is_quiet(self):
        data = random.Random(7).randbytes(2_000_000)
        self.assertEqual(list(scan.scan_content("noise.bin", b"\0" + data)), [])


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class PullRequestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = self.repo = Path(self.tmp.name)
        git(repo, "init", "-q", "-b", "dev-connect-wp")
        git(repo, "config", "user.email", "t@example.com")
        git(repo, "config", "user.name", "t")
        git(repo, "config", "core.autocrlf", "false")
        (repo / "old.php").write_text(f"<?php // legacy {U}\n")   # already on base: not this PR's fault
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "base")
        self.base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        git(repo, "checkout", "-qb", "feature")
        (repo / "src").mkdir()
        (repo / "src" / "x.php").write_text(f"<?php\n// Built by {U} team\n$ok = 1;\n")
        (repo / f"logo-{U}.svg").write_text("<svg/>")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", f"Add {T} branding\n\nSigned-off-by: Dev <dev@{T}solutions.com>")
        self.head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

    def tearDown(self):
        self.tmp.cleanup()

    def test_pr_code_and_commits(self):
        found = scan.scan_pr_code(self.repo, self.base, self.head) + scan.scan_commits(self.repo, f"{self.base}..{self.head}")
        got = sorted((f.kind, f.location()) for f in found)
        self.assertEqual(got, sorted([
            ("code", "src/x.php:2"),
            ("file name", f"logo-{U}.svg"),
            ("commit message", f"commit {self.head[:7]}:1"),
        ]))

    def test_pr_command_end_to_end_posts_to_slack(self):
        received = []

        class Hook(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Hook)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        event = Path(self.tmp.name) / "event.json"
        event.write_text(json.dumps({"pull_request": {
            "number": 7, "title": f"Fix {U} footer", "body": f"line one\nby {T}solutions",
            "html_url": "https://github.com/o/r/pull/7", "user": {"login": "dev1"},
            "head": {"ref": "feature", "sha": self.head},
            "base": {"ref": "dev-connect-wp", "sha": self.base},
        }}))
        env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "CONTENT_POLICY_SLACK_DRY_RUN")}
        env.update(GITHUB_EVENT_PATH=str(event), TARGET_DIR=str(self.repo),
                   SLACK_WEBHOOK_URL=f"http://127.0.0.1:{server.server_port}/", GITHUB_REPOSITORY="o/r")
        result = subprocess.run([sys.executable, str(SCANNER), "pr"], env=env, capture_output=True, text=True)
        server.shutdown()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(len(received), 1)
        message = json.dumps(received[0])
        for expected in ("src/x.php:2", "PR title", "PR description:2", "#L2", "dev1"):
            self.assertIn(expected, message)


class RandomValueTest(unittest.TestCase):
    IGNORED = [
        f"var BUILD_ID = '4f9c1a7b{T}83d0c5k6q';",
        f"const EXPORT_SALT = 'Hq7vT2pLx9{T}Rk4Wd8sZb1N';",
        f"define( 'AUTH_KEY', 'z]8<{T}K#4q!Lw9@Tb^2xP' );",
        f"BUILD_HASH=4f9c1a7b{T}83d0c5k6q",
        f'"integrity": "Kp4x7R{T}Q9z1Lw8Vt3B"',
    ]
    FLAGGED = [
        f"private function get{U}DefaultOptions(): array {{",      # not a value
        f"$key = 'MyPlugin{U}SettingsKey';",                       # words
        f"$c = 'Copyright2024{U}SolutionsLtd';",                   # words
        f"$a = '{T}-logo-2024-final-v3x';",                        # at the start
        f"$a = 'Hq7vT2pLx9_{T}Rk4Wd8sZb1N';",                      # after a separator
        f"$a = 'Hq7vT2pLx9{T}';",                                  # at the end
        f"$u = 'https://cdn.{T}.com/assets/app.js';",              # after a dot
        f"$a = 'x9{T}Rk4';",                                       # too short
        f"$a = 'Hq7vT2pLx9 {T} Rk4Wd8sZb1N';",                     # has spaces
        f"// salt Hq7vT2pLx9{T}Rk4Wd8sZb1N",                       # not quoted/assigned
        f"$a = 'Hq7vT2pLx9{T}Rk4Wd8sZb1N'; // by {U}",            # real hit on the same line
        # Names built from short words, digits and caps (camelCase parts).
        f"$a = 'Sync{U}ClientV2x9';",
        f"$a = 'Dc{U}Sync2024AbCd';",
        f"$a = 'App{U}Key2Val3Run4';",
        f"$a = 'K9{U}V2Api3Cfg4X';",
        f"$a = 'Rq9get{U[:2]}{T[2]}Data2Xy7Lp';",
        f"$a = 'Ab3{U}Xy7Kq9Zr2Lm5Wp';",
    ]

    def test_random_values_are_ignored(self):
        for line in self.IGNORED:
            ignored = []
            self.assertIsNone(scan.match(line, ignored=ignored), line)
            self.assertEqual(len(ignored), 1, line)

    def test_names_are_still_flagged(self):
        for line in self.FLAGGED:
            self.assertIsNotNone(scan.match(line), line)

    def test_ignored_values_are_reported_not_counted(self):
        data = ("<?php\n" + self.IGNORED[1] + "\n" + self.FLAGGED[0] + "\n").encode()
        scan.IGNORED.clear()
        self.assertEqual([n for _, n, _ in scan.scan_content("a.php", data)], [3])
        self.assertEqual(scan.IGNORED, [("a.php:2", f"Hq7vT2pLx9{T}Rk4Wd8sZb1N")])
        scan.IGNORED.clear()


class SlackMentionTest(unittest.TestCase):
    def setUp(self):
        self.saved = os.environ.get("SLACK_USER_MAP")
        os.environ["SLACK_USER_MAP"] = json.dumps({"Dev1": "U012AB3CD", "dev2": "@some-name"})

    def tearDown(self):
        if self.saved is None:
            os.environ.pop("SLACK_USER_MAP", None)
        else:
            os.environ["SLACK_USER_MAP"] = self.saved

    def test_member_id_name_and_unmapped(self):
        users = scan.slack_users()
        self.assertEqual(scan.mention("dev1", users), "<@U012AB3CD> (dev1)")
        self.assertEqual(scan.mention("dev2", users), "*@some-name* (dev2)")
        self.assertEqual(scan.mention("dev3", users), "*dev3*")

    def test_alert_mentions_author_and_commenters(self):
        findings = [scan.Finding("PR title", "PR title", "x"),
                    scan.Finding("comment by dev3", "PR comment", "x", 1, who="dev3"),
                    scan.Finding("review by dev1", "review", "x", 1, who="dev1")]
        intro = scan.slack_alert("PR #1", "", findings, "dev1")["blocks"][1]["text"]["text"]
        self.assertIn("By <@U012AB3CD> (dev1)", intro)
        self.assertIn("Flagged comments by *dev3*", intro)
        self.assertEqual(intro.count("U012AB3CD"), 1)

    def test_bad_json_is_ignored(self):
        os.environ["SLACK_USER_MAP"] = "{not json"
        self.assertEqual(scan.slack_users(), {})


class SelfScanTest(unittest.TestCase):
    def test_kit_is_clean(self):
        kit = HERE.parents[2]
        self.assertEqual([f.location() for f in scan.scan_tree(kit)], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
