"""Update one authenticated user's FUSE PR comment after the scan finishes."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def request(url: str, token: str, method: str = "GET", body: dict[str, str] | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)


def main() -> int:
    token = os.environ["FUSE_COMMENT_TOKEN"]
    repo = os.environ["FUSE_REPOSITORY"]
    number = os.environ["FUSE_PR_NUMBER"]
    api = os.environ["FUSE_API_URL"].rstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not number.isdigit():
        raise ValueError("Invalid repository or pull request number")
    content = (Path(os.environ["FUSE_REVIEW_DIR"]) / "review.md").read_text(encoding="utf-8")
    try:
        login = request(f"{api}/user", token)["login"]
    except urllib.error.HTTPError as error:
        if error.code not in {401, 403}:
            raise
        login = "github-actions[bot]"
    endpoint = f"{api}/repos/{repo}/issues/{number}/comments"
    existing = None
    for page in range(1, 11):
        comments = request(f"{endpoint}?per_page=100&page={page}", token)
        for comment in comments:
            if comment.get("user", {}).get("login") == login and comment.get("body", "").startswith(
                "<!-- fuse-security-review -->"
            ):
                existing = comment["id"]
                break
        if existing or len(comments) < 100:
            break
    if existing:
        request(
            f"{api}/repos/{repo}/issues/comments/{int(existing)}", token, "PATCH", {"body": content}
        )
    else:
        request(endpoint, token, "POST", {"body": content})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, ValueError, OSError, urllib.error.URLError) as error:
        print(f"FUSE PR comment failed: {type(error).__name__}")
        raise SystemExit(1)
