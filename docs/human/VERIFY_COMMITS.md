# Verify every MRML commit

MRML commits are expected to carry a valid OpenPGP signature from the project's
commit-signing key. The procedure below checks every commit reachable from every
local or fetched reference. It stops if a commit is unsigned, has a malformed or
cryptographically invalid signature, or was signed by another key.

The expected primary-key fingerprint is:

```text
6EE7 5495 B042 7A4F 3F97  BA1C 14D7 0434 990F 1CA9
```

Do not replace this fingerprint merely because another key claims the same name
or email address. Confirm it through an independent channel that you trust.

## Current history limitation

The repository contains historical commits that predate mandatory signing. The
strict procedure below therefore reports those commits as unsigned and exits
with failure. This is intentional: an unsigned commit cannot be authenticated
with the public key, and documentation must not describe it as verified.

Retrofitting signatures would rewrite commit objects and change their IDs. This
guide does not instruct readers to rewrite history. It instead provides an
exhaustive audit: success means 100% of reachable commits passed, while any
unsigned, invalid, or differently signed commit prevents that claim.

## 1. Obtain a complete repository

Start with a normal clone and enter it:

```sh
git clone https://git.mrml.ca/mitchellrenouf/mrml.git
cd mrml
```

If an existing checkout is shallow, make its available history complete first:

```sh
if test "$(git rev-parse --is-shallow-repository)" = true; then
    git fetch --unshallow origin
fi
```

Fetch every reference advertised by the server into a separate local namespace.
This includes branches, tags, and other advertised reference families without
overwriting the checkout's own branches:

```sh
git fetch --prune origin '+refs/*:refs/verification/origin/*'
```

This can verify only objects and references the server provides. A server cannot
provide deleted history or references that it deliberately hides from clients.

## 2. Import only the documented key

Use a temporary GnuPG home so personal keys, trust settings, and key-server
configuration cannot affect the result:

```sh
VERIFY_GNUPGHOME="$(mktemp -d)"
chmod 700 "$VERIFY_GNUPGHOME"
export VERIFY_GNUPGHOME
trap 'rm -rf "$VERIFY_GNUPGHOME"' EXIT HUP INT TERM

gpg --homedir "$VERIFY_GNUPGHOME" --batch \
    --import docs/keys/mrml-commit-signing-key.asc

gpg --homedir "$VERIFY_GNUPGHOME" --batch --with-colons \
    --fingerprint 6EE75495B0427A4F3F97BA1C14D70434990F1CA9
```

Inspect the final command's `fpr` record and confirm that it contains exactly
`6EE75495B0427A4F3F97BA1C14D70434990F1CA9`.

## 3. Check repository integrity and every reachable commit

Run the following block from the repository root. It obtains the complete,
deduplicated commit set from all references, asks GnuPG to validate each
signature, and requires the signature's primary key to match the fingerprint
above. A signing subkey is accepted only when GnuPG binds it to that primary
key.

```sh
set -eu

expected=6EE75495B0427A4F3F97BA1C14D70434990F1CA9
commit_list="$(mktemp)"
status_file="$(mktemp)"
trap 'rm -f "$commit_list" "$status_file"; rm -rf "$VERIFY_GNUPGHOME"' \
    EXIT HUP INT TERM

git fsck --full --strict
git rev-list --all >"$commit_list"

test -s "$commit_list" || {
    echo "No reachable commits were found." >&2
    exit 1
}

while IFS= read -r commit; do
    if ! GNUPGHOME="$VERIFY_GNUPGHOME" git verify-commit --raw "$commit" \
        > /dev/null 2>"$status_file"; then
        echo "Invalid or missing signature on $commit" >&2
        cat "$status_file" >&2
        exit 1
    fi

    primary=$(
        awk '/^\[GNUPG:\] VALIDSIG / {
                 fingerprint = $3
                 primary = ($12 == "" ? fingerprint : $12)
             }
             END { print primary }' "$status_file"
    )

    if test "$primary" != "$expected"; then
        echo "Commit $commit was signed by unexpected key $primary" >&2
        exit 1
    fi
done <"$commit_list"

count="$(wc -l <"$commit_list" | tr -d ' ')"
echo "Verified all $count commits reachable from all local and fetched refs."
```

Any nonzero exit means verification did not complete successfully. Do not treat
a partial count as success. Re-fetch and repeat the entire procedure whenever
the remote references change.

## What this verification proves

A successful result proves that the fetched Git objects are internally
consistent and that every reachable commit has a cryptographically valid
signature chaining to the documented public key. It also detects commits signed
by any other key, including a key with a matching user ID.

It does not prove that the signer was authorized for every change, that the
signer's computer or private key was never compromised, that the code is safe or
correct, or that the server disclosed every historical reference. OpenPGP also
does not establish the real-world identity behind a key by itself. Establishing
that identity requires independently authenticating the fingerprint, and
assessing the software still requires review, reproducible builds, and relevant
testing.
