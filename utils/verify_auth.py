#!/usr/bin/env python3
"""verify that registry changes are signed by a key of the object's maintainer"""

import os
import re
import subprocess
import sys
import tempfile

DATA_DIR = "data"
MNTNER_DIR = f"{DATA_DIR}/mntner"
KEYSERVERS = ("hkps://keys.openpgp.org", "hkps://keyserver.ubuntu.com")
SSH_PREFIXES = ("ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"

errors = 0
warnings = 0


def report(kind, message, path=None):
    global errors, warnings
    if kind == "error":
        errors += 1
    else:
        warnings += 1
    if IN_ACTIONS:
        where = f" file={path}" if path else ""
        print(f"::{kind}{where}::{message}")
    else:
        print(f"{kind}: {message}")


def git(*args, check=True):
    proc = subprocess.run(("git",) + args, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def blob(rev, path):
    proc = git("show", f"{rev}:{path}", check=False)
    return proc.stdout if proc.returncode == 0 else None


def object_values(text, key):
    """pull every value of a key out of a registry object, tolerating junk lines"""
    values = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        line_key, value = line.split(":", 1)
        if line_key.strip() == key:
            values.append(value.strip())
    return values


def normalize_fingerprint(value):
    return re.sub(r"[\s:]", "", value).upper()


def load_maintainers(rev):
    """map every mntner at rev to the PGP fingerprints and SSH keys it authorizes with"""
    listing = git("ls-tree", "--name-only", f"{rev}:{MNTNER_DIR}", check=False)
    if listing.returncode != 0:
        raise SystemExit(f"no {MNTNER_DIR} at {rev}")

    maintainers = {}
    for name in listing.stdout.split():
        text = blob(rev, f"{MNTNER_DIR}/{name}")
        if text is None:
            continue
        pgp, ssh = set(), []
        for auth in object_values(text, "auth"):
            fields = auth.split(None, 1)
            if len(fields) != 2:
                report("warning", f"{name}: malformed auth line {auth!r}")
                continue
            method, value = fields[0].lower(), fields[1].strip()
            if method == "pgp-fingerprint":
                fingerprint = normalize_fingerprint(value)
                if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
                    report("warning", f"{name}: bad PGP fingerprint {value!r}")
                    continue
                pgp.add(fingerprint)
            elif method.startswith(SSH_PREFIXES):
                ssh.append(f"{method} {value.split()[0]}")
            else:
                report("warning", f"{name}: unknown auth method {method!r}")
        maintainers[name] = {"pgp": pgp, "ssh": ssh}
    return maintainers


def import_pgp_keys(fingerprints, home):
    """fetch each registered key from a keyserver into an isolated keyring"""
    os.chmod(home, 0o700)
    for fingerprint in sorted(fingerprints):
        for keyserver in KEYSERVERS:
            proc = subprocess.run(
                ["gpg", "--homedir", home, "--batch", "--quiet",
                 "--keyserver", keyserver, "--recv-keys", fingerprint],
                capture_output=True, text=True,
            )
            if proc.returncode == 0:
                break
        else:
            report("warning", f"could not fetch PGP key {fingerprint} from any keyserver")


def write_allowed_signers(maintainers, path):
    with open(path, "w") as file:
        for name, keys in sorted(maintainers.items()):
            for key in keys["ssh"]:
                file.write(f"{name} {key}\n")


def ssh_fingerprint(key, workdir):
    key_path = os.path.join(workdir, "key.pub")
    with open(key_path, "w") as file:
        file.write(key + "\n")
    proc = subprocess.run(["ssh-keygen", "-lf", key_path], capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.split()[1]


def signature_format(sha):
    header = git("cat-file", "commit", sha).stdout.split("\n\n", 1)[0]
    if "BEGIN SSH SIGNATURE" in header:
        return "ssh"
    if "BEGIN PGP SIGNATURE" in header:
        return "openpgp"
    return None


def pgp_signer_fingerprints(sha, home):
    proc = subprocess.run(
        ["git", "-c", "gpg.format=openpgp", "verify-commit", "--raw", sha],
        capture_output=True, text=True, env=dict(os.environ, GNUPGHOME=home),
    )
    status = proc.stderr.splitlines()
    if not any(line.startswith("[GNUPG:] GOODSIG") for line in status):
        return set()
    fingerprints = set()
    for line in status:
        fields = line.split()
        if len(fields) > 2 and fields[1] == "VALIDSIG":
            fingerprints.add(fields[2].upper())
            if len(fields) >= 12:
                fingerprints.add(fields[11].upper())
    return fingerprints


def ssh_signer_fingerprint(sha, allowed_signers):
    proc = subprocess.run(
        ["git", "-c", "gpg.format=ssh",
         "-c", f"gpg.ssh.allowedSignersFile={allowed_signers}", "verify-commit", sha],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    match = re.search(r"SHA256:[A-Za-z0-9+/=]+", proc.stderr)
    return match.group(0) if match else None


def changed_paths(sha):
    """yield (status, path, source_rev) for every path the commit touches"""
    proc = git("diff-tree", "-r", "-M", "--root", "--no-commit-id", "--name-status", sha)
    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        status = fields[0][0]
        if status in ("R", "C"):
            yield "D", fields[1], f"{sha}^"
            yield "A", fields[2], sha
        elif status == "A":
            yield "A", fields[1], sha
        elif status == "D":
            yield "D", fields[1], f"{sha}^"
        else:
            yield "M", fields[1], f"{sha}^"


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(f"usage: {sys.argv[0]} <base-rev> [head-rev]")
    base, head = sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "HEAD"

    maintainers = load_maintainers(base)
    commits = git("rev-list", "--no-merges", "--reverse", f"{base}..{head}").stdout.split()
    if not commits:
        print(f"no commits in {base}..{head}")
        return 0

    with tempfile.TemporaryDirectory() as workdir:
        gnupghome = os.path.join(workdir, "gnupg")
        os.mkdir(gnupghome)
        allowed_signers = os.path.join(workdir, "allowed_signers")

        pgp_index, ssh_index = {}, {}
        all_fingerprints = set()
        for name, keys in maintainers.items():
            for fingerprint in keys["pgp"]:
                pgp_index.setdefault(fingerprint, set()).add(name)
                all_fingerprints.add(fingerprint)
            for key in keys["ssh"]:
                fingerprint = ssh_fingerprint(key, workdir)
                if fingerprint is None:
                    report("warning", f"{name}: unreadable SSH key {key.split()[0]}")
                    continue
                ssh_index.setdefault(fingerprint, set()).add(name)

        if all_fingerprints:
            import_pgp_keys(all_fingerprints, gnupghome)
        write_allowed_signers(maintainers, allowed_signers)

        for sha in commits:
            check_commit(sha, maintainers, gnupghome, allowed_signers, pgp_index, ssh_index)

    print(f"\n{len(commits)} commit(s) checked, {errors} error(s), {warnings} warning(s)")
    return 1 if errors else 0


def check_commit(sha, maintainers, gnupghome, allowed_signers, pgp_index, ssh_index):
    subject = git("log", "-1", "--format=%s", sha).stdout.strip()
    signers = set()
    fmt = signature_format(sha)
    if fmt == "openpgp":
        for fingerprint in pgp_signer_fingerprints(sha, gnupghome):
            signers |= pgp_index.get(fingerprint, set())
    elif fmt == "ssh":
        fingerprint = ssh_signer_fingerprint(sha, allowed_signers)
        if fingerprint is not None:
            signers |= ssh_index.get(fingerprint, set())

    described = ", ".join(sorted(signers)) if signers else "no registered maintainer"
    print(f"\n{sha[:8]} {subject}\n  signature: {fmt or 'none'} -> {described}")

    for status, path, rev in changed_paths(sha):
        if not path.startswith(f"{DATA_DIR}/"):
            report("warning", f"{path} is outside {DATA_DIR}/ and is not covered by mnt-by", path)
            continue

        text = blob(rev, path)
        if text is None:
            report("error", f"cannot read {path} at {rev}", path)
            continue

        required = set(object_values(text, "mnt-by"))
        if not required:
            report("error", f"{path} has no mnt-by, cannot authorize the change", path)
            continue

        unknown = required - maintainers.keys()
        if unknown:
            report("warning", f"{path}: mnt-by names unknown mntner(s) {', '.join(sorted(unknown))}", path)

        holders = {name for name in required & maintainers.keys()
                   if maintainers[name]["pgp"] or maintainers[name]["ssh"]}
        if not holders:
            report("warning",
                   f"{path}: no mntner in mnt-by ({', '.join(sorted(required))}) has auth keys, "
                   f"allowing {status}", path)
            continue

        if signers & holders:
            print(f"  ok {status} {path} ({', '.join(sorted(signers & holders))})")
        else:
            report("error",
                   f"{path}: {status} needs a signature from {' or '.join(sorted(holders))}, "
                   f"got {described}", path)


if __name__ == "__main__":
    sys.exit(main())
