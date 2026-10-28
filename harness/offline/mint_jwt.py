#!/usr/bin/env python3
"""Mints Entra-shaped RS256 JWTs and a matching JWKS, using only the stdlib and
the openssl CLI. For offline gateway policy tests; never for production.

  mint_jwt.py init <dir>
  mint_jwt.py token <dir> --iss ISS --aud AUD [--ttl SECONDS] [--kid KID] [--bad-signature]
"""
import argparse, base64, json, subprocess, sys, time, pathlib


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def openssl(*args, stdin=None):
    return subprocess.run(["openssl", *args], input=stdin, capture_output=True, check=True).stdout


def init(d: pathlib.Path):
    d.mkdir(parents=True, exist_ok=True)
    key = d / "key.pem"
    if not key.exists():
        openssl("genrsa", "-out", str(key), "2048")
    mod = openssl("rsa", "-in", str(key), "-noout", "-modulus").decode().strip().split("=")[1]
    n = bytes.fromhex(mod)
    e = (65537).to_bytes(3, "big")
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key", "n": b64u(n), "e": b64u(e)}]}
    (d / "jwks.json").write_text(json.dumps(jwks))


def token(d: pathlib.Path, iss, aud, ttl, kid, bad_signature):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    # Claim shape of an Entra v2.0 access token for api://<client>/access_as_user.
    claims = {"iss": iss, "aud": aud, "iat": now, "nbf": now, "exp": now + ttl, "ver": "2.0",
              "sub": "test-subject", "oid": "00000000-0000-0000-0000-000000000001",
              "preferred_username": "pilot.user@example.com", "scp": "access_as_user"}
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}"
    sig = openssl("dgst", "-sha256", "-sign", str(d / "key.pem"), stdin=signing_input.encode())
    if bad_signature:
        sig = bytes(len(sig))
    return f"{signing_input}.{b64u(sig)}"


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["init", "token"])
    p.add_argument("dir")
    p.add_argument("--iss"); p.add_argument("--aud")
    p.add_argument("--ttl", type=int, default=600)
    p.add_argument("--kid", default="test-key")
    p.add_argument("--bad-signature", action="store_true")
    a = p.parse_args()
    d = pathlib.Path(a.dir)
    if a.cmd == "init":
        init(d)
    else:
        if not (a.iss and a.aud):
            sys.exit("--iss and --aud are required")
        print(token(d, a.iss, a.aud, a.ttl, a.kid, a.bad_signature))
