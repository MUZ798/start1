# Password Breach Checker

A small command-line tool that checks whether a password has appeared in a
known data breach, using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords)
Pwned Passwords API.

## How it works

This tool uses the **k-Anonymity model**:

1. Your password is hashed locally using SHA-1.
2. Only the **first 5 characters** of that hash are sent to the API.
3. The API returns every hash suffix in the world that shares that prefix
   (usually several hundred).
4. The match against your full hash is done **locally**, on your machine.

This means your real password — and even your full hash — is never sent
over the network. Only an ambiguous 5-character prefix is.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

Interactive mode:
```bash
python main.py
```

Or pass one or more passwords directly as arguments:
```bash
python main.py "password123" "correcthorsebatterystaple"
```

## Example output

```
=== Password Breach Checker ===
(Uses k-Anonymity — your password never leaves your machine in full.)

[!] This password was found in 3,861,493 known data breaches. Do not use it.
```

## Why this is a useful security concept

This project demonstrates:
- **Hashing** (SHA-1) for one-way data transformation
- **k-Anonymity**, a real privacy-preserving technique used in production
  security tools (this is literally how HIBP's own password-breach
  checking on browsers works)
- Safe handling of sensitive input (never logging or transmitting raw
  passwords)

## Possible extensions

- Add a `--file passwords.txt` flag to bulk-check a list
- Add password strength scoring (length, entropy, common patterns) alongside
  the breach check
- Wrap it in a simple Flask/FastAPI endpoint for a web UI
