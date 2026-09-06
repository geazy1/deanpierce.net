"""Read-only bounty status checks. No PR code is downloaded or executed.

This is a deterministic status monitor, not an autonomous AI review or payout
verifier. Run with --self-test for offline checks. Only known public repositories
are queried; the optional ephemeral GitHub token is sent solely to api.github.com.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone, timedelta
import html
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UPSTREAM = "pierce403/deanpierce.net"
FORK = "geazy1/deanpierce.net"
OWNER = "geazy1"
ACKNOWLEDGED = "2026-09-06T21:37:00Z"
TRACKED = {
    3: {"sha": "5a894ed346968af84e6adfcdb30bc494b90c8ea8", "run": 34060676299,
        "file": "docs/talks/platypus.md", "blob": "3db6c1fce48e0652a4e852efc8e2f89c27ca9194"},
    4: {"sha": "944d82d697f1fc09af704b7ed42f811c732e693e", "run": 34061324270,
        "file": "mkdocs.yml", "blob": "9521295c7bd3c97d1935efe267155a213212afb2"},
}
MAX_BYTES = 5_000_000
MAX_PAGES = 10


def dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Unexpected API redirect; manual review required")


class GitHubReadOnly:
    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, path: str):
        allowed = tuple(f"/repos/{repo}/" for repo in (UPSTREAM, FORK))
        if not path.startswith(allowed) or ".." in path or "\\" in path:
            raise ValueError("Repository path is outside the monitor allowlist")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "geazy1-bounty-status",
                   "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get("GH_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request("https://api.github.com" + path, headers=headers, method="GET")
        try:
            with self.opener.open(req, timeout=25) as response:
                body = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GitHub HTTP {exc.code}: status is unknown, not healthy") from None
        if len(body) > MAX_BYTES:
            raise RuntimeError("API response exceeds monitor limit")
        return json.loads(body)

    def pages(self, path: str, key: str | None = None):
        rows = []
        for page in range(1, MAX_PAGES + 1):
            sep = "&" if "?" in path else "?"
            data = self.get(f"{path}{sep}per_page=100&page={page}")
            batch = data[key] if key else data
            if not isinstance(batch, list):
                raise RuntimeError("Unexpected paginated response")
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise RuntimeError("Pagination limit reached; review may be incomplete")


def assess(number: int, expected: dict, data: dict, now: datetime) -> dict:
    pr, run = data["pr"], data["run"]
    if pr["user"]["login"] != OWNER or pr["base"]["repo"]["full_name"] != UPSTREAM:
        raise RuntimeError("PR identity mismatch")
    merged = bool(pr.get("merged"))
    state = "merged" if merged else pr["state"]
    alerts, notes = [], []
    if pr["head"]["sha"] != expected["sha"]:
        alerts.append("PR head changed after the recorded validation; re-review and retest")
    if data["file"]["sha"] != expected["blob"]:
        alerts.append("Current PR file differs from the validated file")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        alerts.append("Recorded validation run is not confirmed successful")
    if state == "open":
        if pr.get("mergeable") is False or pr.get("mergeable_state") == "dirty":
            alerts.append("Merge conflict or non-mergeable PR needs inspection")
        elif pr.get("mergeable") is None:
            notes.append("GitHub has not finished computing mergeability")
        if now - dt(pr["created_at"]) > timedelta(days=7):
            notes.append("Open for more than seven days; consider one courteous follow-up")
    elif merged:
        alerts.append("Merged: confirm deployment and bounty eligibility/payment manually")
    else:
        alerts.append("Closed without merge: read the maintainer decision")

    events = data["comments"] + data["inline_comments"] + data["reviews"]
    fresh = [e for e in events if e.get("user", {}).get("login") != OWNER
             and (e.get("updated_at") or e.get("submitted_at") or e.get("created_at") or "") > ACKNOWLEDGED]
    if fresh:
        alerts.append(f"{len(fresh)} external comment/review update(s) since last acknowledged check")

    # Reviews are ordered by submission time; a later substantive review replaces
    # an earlier decision by that reviewer. COMMENTED does not clear a request.
    decisions = {}
    for review in sorted(data["reviews"], key=lambda x: x.get("submitted_at") or ""):
        if review.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            decisions[review["user"]["login"]] = review["state"]
    if "CHANGES_REQUESTED" in decisions.values():
        alerts.append("An outstanding review requests changes")

    statuses = data["statuses"]
    checks = data["checks"]
    failures = [s for s in statuses if s.get("state") in {"failure", "error"}]
    failures += [c for c in checks if c.get("conclusion") in {
        "failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}]
    if failures:
        alerts.append(f"{len(failures)} current CI check/status failure(s)")
    if not checks and not statuses:
        ci = "No head-SHA checks published; separate validation run passed" if not any("validation run" in a for a in alerts) else "No head-SHA checks published"
    elif any(c.get("status") != "completed" for c in checks) or any(s.get("state") == "pending" for s in statuses):
        ci = "Checks pending" + ("; failures also present" if failures else "")
    else:
        ci = "Failures present" if failures else "Published checks have no reported failures"

    links = []
    for event in fresh:
        url = event.get("html_url", "")
        if url.startswith(f"https://github.com/{UPSTREAM}/"):
            links.append(url)
    return {"pr": number, "url": f"https://github.com/{UPSTREAM}/pull/{number}",
            "state": state, "head": pr["head"]["sha"], "ci": ci,
            "validation_url": f"https://github.com/{FORK}/actions/runs/{expected['run']}",
            "alerts": alerts, "notes": notes, "feedback_links": sorted(set(links)),
            "payment": "UNCONFIRMED: no payout verification is performed by this monitor"}


def collect(api: GitHubReadOnly, number: int, expected: dict) -> dict:
    pr = api.get(f"/repos/{UPSTREAM}/pulls/{number}")
    sha = pr["head"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Invalid head SHA")
    return {"pr": pr,
            "run": api.get(f"/repos/{FORK}/actions/runs/{expected['run']}"),
            "file": api.get(f"/repos/{UPSTREAM}/contents/{expected['file']}?ref={sha}"),
            "comments": api.pages(f"/repos/{UPSTREAM}/issues/{number}/comments"),
            "inline_comments": api.pages(f"/repos/{UPSTREAM}/pulls/{number}/comments"),
            "reviews": api.pages(f"/repos/{UPSTREAM}/pulls/{number}/reviews"),
            "checks": api.pages(f"/repos/{UPSTREAM}/commits/{sha}/check-runs?filter=latest", "check_runs"),
            "statuses": api.pages(f"/repos/{UPSTREAM}/commits/{sha}/status", "statuses")}


def self_test():
    spec = TRACKED[3]
    good = {"pr": {"user": {"login": OWNER}, "base": {"repo": {"full_name": UPSTREAM}},
            "head": {"sha": spec["sha"]}, "state": "open", "merged": False,
            "mergeable": True, "created_at": "2026-09-06T21:20:26Z"},
            "run": {"status": "completed", "conclusion": "success"},
            "file": {"sha": spec["blob"]}, "comments": [], "inline_comments": [],
            "reviews": [], "checks": [], "statuses": []}
    now = dt("2026-09-06T22:00:00Z")
    assert assess(3, spec, good, now)["alerts"] == []
    variants = [
        ("pr", "mergeable", False, "Merge conflict"),
        ("pr", "merged", True, "Merged:"),
        ("pr", "state", "closed", "Closed without"),
        ("run", "conclusion", "failure", "validation run"),
        ("file", "sha", "0" * 40, "validated file"),
    ]
    for section, key, value, text in variants:
        case = copy.deepcopy(good)
        case[section][key] = value
        assert any(text in a for a in assess(3, spec, case, now)["alerts"])
    case = copy.deepcopy(good)
    case["comments"] = [{"user": {"login": "maintainer"}, "updated_at": "2026-09-06T21:45:00Z"}]
    assert any("external comment" in a for a in assess(3, spec, case, now)["alerts"])
    case = copy.deepcopy(good)
    case["reviews"] = [{"user": {"login": "maintainer"}, "state": "CHANGES_REQUESTED", "submitted_at": "2026-09-06T21:00:00Z"}]
    assert any("requests changes" in a for a in assess(3, spec, case, now)["alerts"])
    case["reviews"].append({"user": {"login": "maintainer"}, "state": "APPROVED", "submitted_at": "2026-09-06T21:01:00Z"})
    assert not any("requests changes" in a for a in assess(3, spec, case, now)["alerts"])
    case = copy.deepcopy(good)
    case["checks"] = [{"status": "completed", "conclusion": "failure"}]
    assert any("CI check" in a for a in assess(3, spec, case, now)["alerts"])
    case = copy.deepcopy(good)
    case["pr"]["head"]["sha"] = "1" * 40
    assert any("head changed" in a for a in assess(3, spec, case, now)["alerts"])
    api = GitHubReadOnly()
    try:
        api.get("https://attacker.invalid/")
    except ValueError:
        pass
    else:
        raise AssertionError("External URL accepted")
    print("PASS: 12 offline monitor scenarios (healthy, conflicts, merge, closure, validation, blob, feedback, reviews, CI, head, URL guard)")


def main() -> int:
    now = datetime.now(timezone.utc)
    results = []
    api = GitHubReadOnly()
    for number, expected in TRACKED.items():
        try:
            results.append(assess(number, expected, collect(api, number, expected), now))
        except Exception as exc:
            results.append({"pr": number, "url": f"https://github.com/{UPSTREAM}/pull/{number}",
                "state": "UNKNOWN", "alerts": [f"Read failed: {type(exc).__name__}. Do not treat this PR as healthy."],
                "notes": [], "feedback_links": [], "payment": "UNCONFIRMED"})
    report = {"checked_at_utc": now.isoformat(), "scope": list(TRACKED), "results": results,
              "cash_received_verified": False, "mode": "read-only deterministic status monitor"}
    Path("bounty-status.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# Bounty submission status", "", f"Checked (UTC): {now.isoformat()}", "",
        "Read-only status checks. No automatic code review, edits, replies, merges, transfers, or payout verification.", ""]
    for row in results:
        lines += [f"## PR #{row['pr']}: {row['state']}", "", row["url"], "",
                  row.get("ci", "CI state unknown"), "", f"Payment: {row['payment']}", ""]
        lines += ["- " + html.escape(a) for a in row["alerts"] + row["notes"]]
        if not row["alerts"]:
            lines.append("No new actionable flags. Awaiting maintainer review is not a payout.")
        lines.extend(row["feedback_links"])
        lines.append("")
    text = "\n".join(lines)
    Path("bounty-status.md").write_text(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(text)
    print(json.dumps(report, indent=2))
    if any(row["alerts"] for row in results):
        print("::error::Bounty status needs attention; inspect this run's summary. No automated edits were made.")
        return 1
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        sys.exit(main())
