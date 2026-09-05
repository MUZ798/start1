"""
Password Breach Checker
------------------------
Checks whether a password has appeared in known data breaches using the
"Have I Been Pwned" Pwned Passwords API.

Security note: this uses the k-Anonymity model. Your password is hashed
locally with SHA-1, and only the FIRST 5 CHARACTERS of that hash are sent
to the API. The API returns all hash suffixes that share that prefix, and
the match is done locally. The full password (and full hash) never leaves
your machine.
"""

import hashlib
import sys
import requests

API_URL = "https://api.pwnedpasswords.com/range/"


def get_password_hash(password: str) -> tuple[str, str]:
    """Return (prefix, suffix) of the SHA-1 hash of the password, uppercase."""
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1_hash[:5], sha1_hash[5:]


def query_api(prefix: str) -> str:
    """Query the Pwned Passwords API with a hash prefix. Returns raw response text."""
    url = API_URL + prefix
    response = requests.get(url, timeout=10)

    if response.status_code != 200:
        raise RuntimeError(
            f"Error fetching data from API: status code {response.status_code}"
        )

    return response.text


def check_password_breach(password: str) -> int:
    """
    Check if a password has been breached.
    Returns the number of times it appeared in breaches (0 if not found).
    """
    prefix, suffix = get_password_hash(password)
    response_text = query_api(prefix)

    hashes = (line.split(":") for line in response_text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return int(count)

    return 0


def main():
    print("=== Password Breach Checker ===")
    print("(Uses k-Anonymity — your password never leaves your machine in full.)\n")

    if len(sys.argv) > 1:
        passwords = sys.argv[1:]
    else:
        pw = input("Enter a password to check: ")
        passwords = [pw]

    for pw in passwords:
        try:
            count = check_password_breach(pw)
        except RuntimeError as e:
            print(f"[ERROR] Could not check password: {e}")
            continue

        if count:
            print(
                f"[!] This password was found in {count:,} known data breaches. "
                "Do not use it."
            )
        else:
            print("[OK] This password was not found in any known breaches.")


if __name__ == "__main__":
    main()
