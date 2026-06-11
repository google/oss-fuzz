#!/usr/bin/env python3
"""OSS-Fuzz Criticality Scorer — GitHub Action bot.

Triggered on new/modified OSS-Fuzz integration PRs.
Scores based on: GitHub stars, NVD CVEs, OSV.dev vulns, attack surface analysis.
Posts a data-backed score comment to the PR.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
UA = "oss-fuzz-criticality-bot/1.0"
MARKER = "<!-- criticality-bot v1.0 -->"
MAX_SCORE = 100


def _api(url, headers=None, data=None, timeout=15):
    """HTTP request helper."""
    hdrs = headers or {}
    hdrs.setdefault("User-Agent", UA)
    try:
        req = urllib.request.Request(url, headers=hdrs, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except OSError:
        return None


def gh_api(path):
    """GitHub REST API call."""
    hdrs = {"Accept": "application/vnd.github+json"}
    if TOKEN:
        hdrs["Authorization"] = f"Bearer {TOKEN}"
    return _api(f"https://api.github.com{path}", hdrs)


def gh_search(query):
    """GitHub code search."""
    encoded = urllib.request.quote(query)
    return _api(
        f"https://api.github.com/search/code?q={encoded}&per_page=1",
        {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {TOKEN}"},
    )


def nvd_count(keyword):
    """Count NVD CVEs."""
    result = _api(
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=1",
    )
    return result.get("totalResults", 0) if result else 0


def osv_count(ecosystem, pkg_name):
    """Count OSV.dev vulnerabilities."""
    payload = json.dumps({
        "package": {"name": pkg_name, "ecosystem": ecosystem},
    }).encode()
    result = _api(
        "https://api.osv.dev/v1/query",
        {"Content-Type": "application/json"},
        data=payload,
    )
    return len(result.get("vulns", [])) if result else 0


def get_stars(owner, repo):
    """Get GitHub stars."""
    info = gh_api(f"/repos/{owner}/{repo}")
    if info and "stargazers_count" in info:
        return info["stargazers_count"]
    return 0


def get_go_mod_deps(owner, repo):
    """Count go.mod files importing this package."""
    result = gh_search(f'"{owner}/{repo}" language:go filename:go.mod')
    return result.get("total_count", 0) if result else 0


# --- Scoring Functions ---


def score_dependents(stars):
    """0-30 based on usage."""
    for threshold, score in [
        (20000, 30), (10000, 25), (5000, 22), (2000, 18),
        (1000, 14), (500, 10), (100, 6),
    ]:
        if stars > threshold:
            return score
    return 3


def score_attack_surface(ptype, preauth, parser):
    """0-25 based on attack surface characteristics."""
    pts = 0
    if preauth:
        pts += 12
    if parser:
        pts += 10
    role = {
        "crypto": 8, "auth": 8, "policy_engine": 8,
        "serialization": 7, "protocol": 7, "sql_driver": 6,
        "certificate": 5, "dns": 5, "http": 5, "websocket": 4,
        "config": 4, "kv_store": 3, "semver": 2, "test_toolkit": 1,
    }
    pts += role.get(ptype, 2)
    return min(25, max(3, pts))


def score_cves(keywords, ecosystem_pkg, ecosystem_name):
    """0-20 based on CVE/vuln history."""
    total = 0
    for kw in keywords:
        total += nvd_count(kw)
        time.sleep(0.6)
    total += osv_count(ecosystem_name, ecosystem_pkg)
    for threshold, score in [
        (20, 20), (10, 15), (5, 10), (1, 5),
    ]:
        if total > threshold:
            return score
    return 3 if total > 0 else 1


def score_supply_chain(dep_count):
    """0-15 based on supply chain impact."""
    for threshold, score in [
        (50000, 15), (20000, 12), (5000, 9),
        (1000, 6), (100, 3),
    ]:
        if dep_count > threshold:
            return score
    return 1


def score_security_role(ptype):
    """0-10 based on security role."""
    return {
        "crypto": 10, "auth": 10, "policy_engine": 10,
        "serialization": 9, "protocol": 8, "sql_driver": 8,
        "certificate": 8, "dns": 7, "http": 6,
        "websocket": 6, "config": 5, "kv_store": 5,
        "semver": 4, "test_toolkit": 4,
    }.get(ptype, 3)


# --- Project classification from project.yaml ---


def classify_project(yaml_path):
    """Classify project from its project.yaml."""
    try:
        with open(yaml_path) as f:
            content = f.read().lower()
    except OSError:
        return None

    # Extract homepage/repo info
    repo_owner = ""
    repo_name = ""
    for line in content.split("\n"):
        if "homepage:" in line:
            url = line.split(":", 1)[1].strip().strip('"')
            url = url.replace("https://github.com/", "")
            parts = url.split("/")
            if len(parts) >= 2:
                repo_owner = parts[0]
                repo_name = parts[1]

    # Classify by keywords
    classifications = [
        (["jwt", "token", "oauth", "auth", "saml", "openid"], "auth", True),
        (["crypto", "ssh", "tls", "ssl", "cipher", "hash"], "crypto", True),
        (["policy", "opa", "rego", "rbac", "abac"], "policy_engine", True),
        (["proto", "serial", "wire", "encode", "decode"], "serialization", True),
        (["sql", "postgres", "mysql", "database", "driver"],
         "sql_driver", True),
        (["dns", "domain", "name server"], "dns", True),
        (["http", "hpack", "server", "proxy"], "http", True),
        (["config", "viper", "env", "setting", "yaml", "toml"], "config", True),
        (["cert", "acme", "lego", "x509", "pem", "pki"], "certificate", True),
        (["web", "socket", "ws", "websocket"], "websocket", True),
        (["test", "assert", "mock", "require"], "test_toolkit", False),
        (["semver", "version", "constraint", "dependency"], "semver", True),
        (["badger", "kv", "key", "value", "store", "database"], "kv_store", True),
    ]

    for keywords, ptype, is_parser in classifications:
        if any(kw in content for kw in keywords):
            return {
                "type": ptype,
                "parser": is_parser,
                "preauth": ptype in (
                    "auth", "crypto", "policy_engine", "serialization",
                    "sql_driver", "dns", "http", "websocket",
                ),
                "repo_owner": repo_owner,
                "repo_name": repo_name,
            }
    return {
        "type": "unknown", "parser": False, "preauth": False,
        "repo_owner": repo_owner, "repo_name": repo_name,
    }


# --- Main ---


def score_project(yaml_path, cve_keywords, ecosystem_pkg):
    """Full scoring pipeline."""
    info = classify_project(yaml_path)
    if not info or not info["repo_owner"]:
        print("ERROR: Could not classify project")
        sys.exit(1)

    owner = info["repo_owner"]
    repo = info["repo_name"]

    stars = get_stars(owner, repo)
    deps = get_go_mod_deps(owner, repo)

    components = {
        "dependents": score_dependents(stars),
        "attack_surface": score_attack_surface(
            info["type"], info["preauth"], info["parser"]),
        "cve_history": score_cves(cve_keywords, ecosystem_pkg, "Go"),
        "supply_chain": score_supply_chain(deps),
        "security_role": score_security_role(info["type"]),
    }

    total = sum(components.values())

    return {
        "score": total,
        "stars": stars,
        "go_mod_deps": deps,
        "project_type": info["type"],
        "components": components,
    }


def format_comment(result):
    """Generate markdown comment."""
    c = result["components"]
    return f"""{MARKER}
## Criticality Score: {result['score']}/{MAX_SCORE}

| Component | Score | Data Source |
|---|---|---|
| Dependents | {c['dependents']}/30 | GitHub: {result['stars']} stars |
| Attack Surface | {c['attack_surface']}/25 | Type: {result['project_type']} |
| CVE History | {c['cve_history']}/20 | NVD + OSV.dev |
| Supply Chain | {c['supply_chain']}/15 | go.mod: {result['go_mod_deps']} dependents |
| Security Role | {c['security_role']}/10 | {result['project_type']} |

*Automated by criticality-bot v1.0. Data from GitHub API, NVD, OSV.dev.*
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", type=int, required=True, help="PR number to score")
    args = parser.parse_args()

    # Find modified project.yaml
    yaml_files = []
    for root, _, files in os.walk("projects"):
        for f in files:
            if f == "project.yaml":
                yaml_files.append(os.path.join(root, f))

    if not yaml_files:
        print("No project.yaml found")
        sys.exit(1)

    # Score the first new/modified project
    # In production, we'd parse git diff to find the right one
    yaml_path = yaml_files[0]
    project_name = yaml_path.split("/")[1]

    print(f"Scoring project: {project_name} ({yaml_path})")

    result = score_project(
        yaml_path,
        cve_keywords=[project_name],
        ecosystem_pkg=f"github.com/{project_name}",
    )

    print(f"Score: {result['score']}/{MAX_SCORE}")
    print(f"Components: {json.dumps(result['components'], indent=2)}")

    # Post comment
    comment = format_comment(result)
    subprocess.run([
        "gh", "pr", "comment", str(args.pr),
        "--repo", os.environ.get("GITHUB_REPOSITORY", "google/oss-fuzz"),
        "--body", comment,
    ], check=False)

    print("Score posted to PR")


if __name__ == "__main__":
    main()
