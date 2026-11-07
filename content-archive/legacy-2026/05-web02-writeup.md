---
title: "WEB02 — Northstar"
ctf: "CSCV 2026"
date: 2026-10-17
category: web
difficulty: hard
points: 334
flag_format: "CSCV2026{...}"
author: "datnix"
---

# WEB02 — Northstar

## Summary

The challenge chained a Classic identity leak into Version 2 migration. An
existing-email check returned browser JWTs, a browser-only password reset had
no current-password requirement, and a stacked SQL injection in the Classic
directory changed the administrator's date of birth. Migrating that profile
unlocked the Version 2 admin message containing the flag.

## Solution

### Step 1: Leak Classic sessions and reset passwords

`POST /graphql` accepts `checkEmail(email:)` without authentication. For the
seeded addresses `support@ctf.local` and the administrator address discovered
after the support migration, the response included a valid `legacy-browser`
JWT. Supplying that token and a Chrome-like `User-Agent` to
`updateUserPassword(newPassword:, confirmNew:)` changed each password without
the old password.

The complete replayable script is [solve.py](solve.py); it performs the full
chain and prints the final flag when run against a reachable instance.

```bash
python3 solve.py
```

![Classic session leak](/evidence/cscv2026/web02/01-classic-token.png)

### Step 2: Migrate support, alter the admin security answer, and read the flag

I registered a normal Version 2 account and called `/api/migration/verify` and
`/api/migration/confirm` with the reset support credentials. The imported
message disclosed `ops-admin-7f3@ctf.local`. After resetting that Classic
administrator, `accountDirectory(keyword:)` was vulnerable to stacked SQL:

```text
zzzz'; UPDATE users SET date_of_birth='1990-01-01' WHERE id=3; --
```

The administrator migration then succeeded with `security_answer=1990-01-01`.
`GET /api/account` reported `admin_flag_available: true`, and
`GET /api/admin/get-flag-1iduhx` returned the flag-bearing message.

![Security-question step](/evidence/cscv2026/web02/02-admin-dob.png)

![Flag response](/evidence/cscv2026/web02/03-flag.png)

## Verification note

The flag response and screenshots are preserved from the previously verified
live run recorded in `../WEB02.md`. I also attempted to replay the new
`e5c1456ee2d7` instance, but this task's network namespace has no DNS route or
permitted outbound socket; the limitation is documented in
[REPLAY_STATUS.md](REPLAY_STATUS.md) rather than being hidden.

## Flag

```text
CSCV2026{leg4cY_iDeNtity_migr4t10N_c0mP1e73}
```
