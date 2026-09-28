#!/usr/bin/env python3
"""Build, sign and verify the Ed25519 manifests that authenticate published models.

Clients (threatmodels-rs `authenticity` module, EDAMAME 2.0.2+) fetch
`signed/manifest-<scope>.json` and `signed/manifest-<scope>.sig.json` next to
the models and refuse any model whose SHA-256 is not listed in a manifest
signed by a trusted key. The legacy `<name>.sig` files are NOT touched: they
stay what released clients compare against.

Scopes:
  exec  threatmodel-*.json -- their cli targets run elevated in the helper.
        Signed ONLY with an offline root key (`sign --key root.pem`).
  data  *-db.json and consent/* -- may be signed by the CI key, whose
        certificate (`certify`) is signed by a root key and expires.

Private keys are PKCS#8 PEM Ed25519 keys (`openssl genpkey -algorithm ed25519`
or `keygen`), read from a file (--key) or an environment variable
(--key-env). They are never written into the repository.

Subcommands:
  keygen   --out PATH                         new private key (0600), prints public key + key id
  pubkey   --key PATH | --key-env VAR         print public key hex + key id
  certify  --root-key PATH --public-key HEX --days N --out cert.json
  build    --scope S [--branch main]          (re)write signed/manifest-S.json if content changed
  sign     --scope S (--key PATH | --key-env VAR) [--certificate cert.json | --certificate-env VAR]
  verify   --scope S --public-key HEX [--public-key HEX ...] [--branch main]
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = Path(__file__).resolve().parents[2]
FORMAT = 1
MANIFEST_DOMAIN = b"edamame-models-manifest-v1\n"
CERT_DOMAIN = b"edamame-models-signing-cert-v1\n"
MAX_CERT_DAYS = 90
SCOPES = ("exec", "data")


def scope_files(scope: str, root: Path) -> list[str]:
    if scope == "exec":
        patterns = ["threatmodel-*.json"]
    else:
        patterns = ["*-db.json", "consent/*"]
    found: set[str] = set()
    for pattern in patterns:
        for path in glob.glob(str(root / pattern)):
            if os.path.isfile(path):
                found.add(Path(path).relative_to(root).as_posix())
    return sorted(found)


def manifest_path(root: Path, scope: str) -> Path:
    return root / "signed" / f"manifest-{scope}.json"


def signature_path(root: Path, scope: str) -> Path:
    return root / "signed" / f"manifest-{scope}.sig.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


def load_private(path: str | None, env: str | None) -> Ed25519PrivateKey:
    if path:
        data = Path(path).read_bytes()
    elif env:
        value = os.environ.get(env, "")
        if not value.strip():
            sys.exit(f"environment variable {env} is empty")
        data = value.encode()
    else:
        sys.exit("a private key is required (--key or --key-env)")
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("the private key is not an Ed25519 key")
    return key


def certificate_message(kid: str, public_hex: str, not_after: int) -> bytes:
    return CERT_DOMAIN + f"{kid}\n{public_hex}\n{not_after}\n".encode()


def dump(data: dict) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()


# ---------------------------------------------------------------- commands


def cmd_keygen(args: argparse.Namespace) -> None:
    out = Path(args.out)
    if out.exists():
        sys.exit(f"{out} already exists")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    public = raw_public(key.public_key())
    print(f"public_key {public.hex()}\nkey_id     {key_id(public)}")


def cmd_pubkey(args: argparse.Namespace) -> None:
    public = raw_public(load_private(args.key, args.key_env).public_key())
    print(f"public_key {public.hex()}\nkey_id     {key_id(public)}")


def cmd_certify(args: argparse.Namespace) -> None:
    if args.days <= 0 or args.days > MAX_CERT_DAYS:
        sys.exit(f"--days must be between 1 and {MAX_CERT_DAYS}")
    root = load_private(args.root_key, None)
    public_hex = args.public_key.strip().lower()
    public = bytes.fromhex(public_hex)
    if len(public) != 32:
        sys.exit("--public-key must be a 32-byte Ed25519 key in hex")
    kid = key_id(public)
    not_after = int(args.now or time.time()) + args.days * 86400
    root_public = raw_public(root.public_key())
    cert = {
        "key_id": kid,
        "public_key": public_hex,
        "not_after": not_after,
        "root_key_id": key_id(root_public),
        "root_signature": root.sign(certificate_message(kid, public_hex, not_after)).hex(),
    }
    Path(args.out).write_bytes(dump(cert))
    print(f"certified {kid} until {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(not_after))} by root {cert['root_key_id']}")


def cmd_build(args: argparse.Namespace) -> None:
    root = Path(args.root)
    files = {path: sha256_file(root / path) for path in scope_files(args.scope, root)}
    if not files:
        sys.exit(f"no files found for scope {args.scope}")
    target = manifest_path(root, args.scope)
    previous = json.loads(target.read_bytes()) if target.exists() else None
    if (
        previous
        and previous.get("files") == files
        and previous.get("branch") == args.branch
        and previous.get("scope") == args.scope
    ):
        print(f"{target.relative_to(root)} unchanged (sequence {previous['sequence']})")
        return
    now = int(args.now or time.time())
    sequence = max(now, int(previous["sequence"]) + 1 if previous else 0)
    manifest = {
        "format": FORMAT,
        "scope": args.scope,
        "branch": args.branch,
        "sequence": sequence,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "files": files,
    }
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(dump(manifest))
    # A new manifest invalidates every existing signature.
    sig = signature_path(root, args.scope)
    if sig.exists():
        sig.unlink()
    print(f"wrote {target.relative_to(root)} (sequence {sequence}, {len(files)} files); sign it next")


def cmd_sign(args: argparse.Namespace) -> None:
    root = Path(args.root)
    target = manifest_path(root, args.scope)
    manifest = target.read_bytes()
    key = load_private(args.key, args.key_env)
    public = raw_public(key.public_key())
    kid = key_id(public)
    entry: dict = {"key_id": kid, "signature": key.sign(MANIFEST_DOMAIN + manifest).hex()}

    cert_text = None
    if args.certificate:
        cert_text = Path(args.certificate).read_text()
    elif args.certificate_env:
        cert_text = os.environ.get(args.certificate_env, "")
    if cert_text and cert_text.strip():
        if args.scope == "exec":
            sys.exit("exec manifests are signed with a root key only; refusing a certificate")
        cert = json.loads(cert_text)
        if cert.get("key_id") != kid or cert.get("public_key", "").lower() != public.hex():
            sys.exit("the certificate does not certify this signing key")
        if int(cert["not_after"]) <= time.time():
            sys.exit("the certificate has expired; ask for a new one (certify)")
        entry["certificate"] = cert

    sig = signature_path(root, args.scope)
    envelope = json.loads(sig.read_bytes()) if sig.exists() else {"format": FORMAT, "signatures": []}
    envelope["signatures"] = [e for e in envelope["signatures"] if e.get("key_id") != kid] + [entry]
    sig.write_bytes(dump(envelope))
    print(f"signed {target.relative_to(root)} with {kid}{' (delegated)' if 'certificate' in entry else ' (root)'}")


def verify_entry(entry: dict, message: bytes, roots: dict[str, bytes], scope: str, now: float) -> str:
    signature = bytes.fromhex(entry["signature"])
    cert = entry.get("certificate")
    if cert is None:
        public = roots.get(entry["key_id"])
        if public is None:
            raise ValueError("not a trusted root key")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return "root"
    if scope == "exec":
        raise ValueError("exec manifests require a root signature")
    root_public = roots.get(cert["root_key_id"])
    if root_public is None:
        raise ValueError(f"certificate root {cert['root_key_id']} is not trusted")
    public_hex = cert["public_key"].lower()
    public = bytes.fromhex(public_hex)
    if key_id(public) != cert["key_id"] or cert["key_id"] != entry["key_id"]:
        raise ValueError("certificate key id mismatch")
    Ed25519PublicKey.from_public_bytes(root_public).verify(
        bytes.fromhex(cert["root_signature"]),
        certificate_message(cert["key_id"], public_hex, int(cert["not_after"])),
    )
    if now > int(cert["not_after"]):
        raise ValueError("certificate expired")
    Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    return "delegated"


def cmd_verify(args: argparse.Namespace) -> None:
    root = Path(args.root)
    roots: dict[str, bytes] = {}
    for value in args.public_key:
        for item in value.replace(",", " ").split():
            public = bytes.fromhex(item)
            roots[key_id(public)] = public
    if not roots:
        sys.exit("no trusted public key given")
    manifest_bytes = manifest_path(root, args.scope).read_bytes()
    envelope = json.loads(signature_path(root, args.scope).read_bytes())
    message = MANIFEST_DOMAIN + manifest_bytes
    accepted = None
    problems = []
    for entry in envelope.get("signatures", []):
        try:
            accepted = f"{entry['key_id']} ({verify_entry(entry, message, roots, args.scope, time.time())})"
            break
        except (ValueError, InvalidSignature, KeyError) as error:
            problems.append(f"{entry.get('key_id')}: {error or 'bad signature'}")
    if accepted is None:
        sys.exit(f"no valid signature for scope {args.scope}: {'; '.join(problems) or 'no signature'}")

    manifest = json.loads(manifest_bytes)
    errors = []
    if manifest.get("scope") != args.scope:
        errors.append(f"manifest scope {manifest.get('scope')}")
    if manifest.get("branch") != args.branch:
        errors.append(f"manifest branch {manifest.get('branch')}")
    listed = manifest.get("files", {})
    for path in scope_files(args.scope, root):
        if path not in listed:
            errors.append(f"{path} is not in the manifest")
        elif listed[path] != sha256_file(root / path):
            errors.append(f"{path} does not match the manifest")
    for path in listed:
        if not (root / path).is_file():
            errors.append(f"{path} is listed but missing")
    if errors:
        sys.exit("manifest out of date: " + "; ".join(errors))
    print(f"{args.scope}: {len(listed)} files verified, sequence {manifest['sequence']}, signed by {accepted}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=str(ROOT), help="repository root (default: this checkout)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("pubkey")
    p.add_argument("--key")
    p.add_argument("--key-env")
    p.set_defaults(func=cmd_pubkey)

    p = sub.add_parser("certify")
    p.add_argument("--root-key", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--days", type=int, default=MAX_CERT_DAYS)
    p.add_argument("--out", required=True)
    p.add_argument("--now", type=int, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_certify)

    p = sub.add_parser("build")
    p.add_argument("--scope", choices=SCOPES, required=True)
    p.add_argument("--branch", default="main")
    p.add_argument("--now", type=int, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("sign")
    p.add_argument("--scope", choices=SCOPES, required=True)
    p.add_argument("--key")
    p.add_argument("--key-env")
    p.add_argument("--certificate")
    p.add_argument("--certificate-env")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify")
    p.add_argument("--scope", choices=SCOPES, required=True)
    p.add_argument("--public-key", action="append", default=[])
    p.add_argument("--branch", default="main")
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
