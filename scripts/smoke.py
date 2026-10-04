#!/usr/bin/env python3
"""Reproduce the EK1 foundation through its public HTTP interface."""

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    def request(method, path, expected, payload=None, token=None):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        if status != expected:
            raise RuntimeError(f"{method} {path}: expected {expected}, got {status}")
        return json.loads(body) if body else None

    request("GET", "/healthz", 200)
    request("GET", "/readyz", 200)
    print("OK: HTTP server and PostgreSQL readiness")

    login = "demo_" + secrets.token_hex(6)
    password = "Demo_" + secrets.token_urlsafe(24)
    user = request("POST", "/api/register", 201,
                   {"login": login, "password": password, "name": "Учебный ученик", "role": "student"})["user"]
    if user["login"] != login or user["role"] != "student" or not user["id"]:
        raise RuntimeError("registration returned an unexpected profile")
    if any(key in user for key in ("password", "password_hash", "token")):
        raise RuntimeError("registration exposed credentials")
    print("OK: registration")

    request("GET", "/api/me", 401)
    request("POST", "/api/login", 401, {"login": login, "password": "IncorrectPassword123!"})
    session = request("POST", "/api/login", 200, {"login": login, "password": password})
    token = session["token"]
    profile = request("GET", "/api/me", 200, token=token)["user"]
    if profile != user:
        raise RuntimeError("authenticated profile differs from the registered user")
    print("OK: login, own profile and refusal without a session")

    request("POST", "/api/logout", 204, token=token)
    request("GET", "/api/me", 401, token=token)
    print("OK: logout revokes the session")
    print("EK1 foundation smoke check passed; planned business scenarios were not tested.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, KeyError, json.JSONDecodeError, urllib.error.URLError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
