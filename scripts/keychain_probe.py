"""Round-trip a secret through the OS keyring, the way the daemon's keystore does.

CI runs this on macOS to see whether the login Keychain is usable on a hosted
runner. Exit status 0 means the keyring works; the daemon's ``auto`` keystore
falls back to 0600 files when it does not.
"""

import sys

import keyring
import keyring.errors

SERVICE = "agentconnect-ci-probe"
USER = "probe"


def main() -> int:
    backend = keyring.get_keyring()
    print(f"backend: {type(backend).__module__}.{type(backend).__qualname__}")
    try:
        keyring.set_password(SERVICE, USER, "probe-value")
        ok = keyring.get_password(SERVICE, USER) == "probe-value"
        keyring.delete_password(SERVICE, USER)
    except keyring.errors.KeyringError as exc:
        print(f"keyring unusable: {type(exc).__name__}")
        return 1
    print("round trip ok" if ok else "round trip returned a different value")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
