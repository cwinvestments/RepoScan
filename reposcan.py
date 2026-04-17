#!/usr/bin/env python3
"""
RepoScan™ — Pre-Install Security Scanner v2.0.0
by CW Affiliate Investments LLC

Scans npm packages and GitHub repos for malicious patterns,
prompt injection attacks, typosquatting, and supply chain threats
before you install or clone anything.

Free forever. No dependencies. Pure Python stdlib.
https://github.com/cwinvestments/reposcan

Want continuous monitoring, tarball inspection, alerts & a dashboard?
→ ShieldStack™: https://shieldstack.io
"""

import argparse
import json
import os
import re
import sys
import threading
import difflib
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── ANSI Colors ──
R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; C = "\033[96m"
B = "\033[94m"; M = "\033[95m"; W = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ███████╗██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗  ║
║   ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗ ║
║   ██████╔╝█████╗  ██████╔╝██║   ██║███████╗██║     ███████║██╔██╗ ║
║   ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║╚════██║██║     ██╔══██║██║╚██╗ ║
║   ██║  ██║███████╗██║     ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚█║ ║
║   ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚╝ ║
║                                                              ║
║         Pre-Install Security Scanner™  v2.0.0               ║
║         by CW Affiliate Investments LLC  •  Free Forever     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""

# ── Top 100 popular npm packages for typosquat detection ──
POPULAR_PACKAGES = [
    "lodash","express","react","react-dom","axios","moment","chalk",
    "commander","dotenv","webpack","babel-core","typescript","eslint",
    "prettier","jest","mocha","nodemon","socket.io","mongoose","sequelize",
    "passport","jsonwebtoken","bcrypt","multer","sharp","uuid","async",
    "underscore","jquery","bootstrap","tailwindcss","next","nuxt","vue",
    "angular","svelte","vite","rollup","parcel","esbuild","turbo",
    "prisma","drizzle-orm","knex","pg","mysql2","redis","ioredis",
    "stripe","twilio","sendgrid","aws-sdk","firebase","supabase",
    "openai","anthropic","langchain","zod","yup","formik","react-hook-form",
    "framer-motion","three","d3","chart.js","recharts","date-fns",
    "dayjs","luxon","winston","pino","morgan","helmet","cors","compression",
    "body-parser","cookie-parser","express-session","connect-redis",
    "cross-env","rimraf","glob","minimist","yargs","inquirer","ora",
    "boxen","figlet","kleur","picocolors","debug","semver","node-fetch",
    "got","superagent","cheerio","puppeteer","playwright","cypress",
    "cline","cursor","copilot","claude","openai-node",
]

# ── Prompt Injection Patterns ──
PROMPT_INJECTION_PATTERNS = [
    # ── Classic instruction override ──
    r"ignore (previous|all|above|prior) instructions",
    r"disregard (previous|all|above|prior)",
    r"forget (everything|all|previous)",
    r"you are now",
    r"act as (an? )?(admin|root|superuser|unrestricted|ai without|assistant without)",
    r"jailbreak",
    r"DAN mode",
    r"bypass (security|restrictions|safety|filter)",
    r"new (persona|role|instructions|system prompt)",
    r"override (safety|restrictions|system|instructions)",
    r"you must (now|only|always|immediately)",
    r"from now on (you|ignore|act|respond)",

    # ── LLM delimiter injection (the Cline attack vector) ──
    r"\[SYSTEM\]",
    r"\[INST\]",
    r"\[\/INST\]",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"<<SYS>>",
    r"\[SYS\]",
    r"###\s*(Instruction|System|Human|Assistant)",
    r"Human:\s",
    r"Assistant:\s",
    r"System:\s",

    # ── Token/credential exfiltration commands ──
    r"(export|send|leak|exfiltrate|output|print|echo|log|post).{0,40}(token|secret|key|credential|password|api.?key|npm.?token|auth)",
    r"(npm.?token|NPM_TOKEN|NODE_AUTH_TOKEN)",
    r"(access.?token|ACCESS_TOKEN|GITHUB_TOKEN|GH_TOKEN)",
    r"curl.{0,60}(token|secret|key|credential)",
    r"fetch.{0,60}(token|secret|key|credential)",
    r"http.{0,30}\.(sh|py|exe).{0,30}(token|secret)",

    # ── AI agent instruction hijacking ──
    r"STOP\. NEW INSTRUCTIONS",
    r"execute (the following|this command|immediately)",
    r"run (the following|this command|immediately)",
    r"(label|close|assign|merge|approve).{0,30}(this|the) (issue|pr|pull request)",
    r"add (label|comment|reaction).{0,40}(issue|pr)",
    r"you (are|have been) (now |re)?programmed",
    r"new task:",
    r"priority (task|instruction|command):",
    r"(admin|operator|developer) mode",
    r"maintenance mode",
    r"debug mode.{0,20}(enable|on|activate)",

    # ── Indirect injection via formatting tricks ──
    r"```\s*(system|instructions?|prompt)",
    r"---\s*system\s*---",
    r"={3,}\s*system\s*={3,}",
    r"\*\*\s*system\s*\*\*",
]

# ── Malicious Script Patterns ──
MALICIOUS_SCRIPT_PATTERNS = [
    (r"curl\s+.*\s*\|\s*(sh|bash|zsh)", "Remote code execution via curl pipe"),
    (r"wget\s+.*\s*\|\s*(sh|bash|zsh)", "Remote code execution via wget pipe"),
    (r"eval\s*\(", "Dynamic code evaluation"),
    (r"exec\s*\(", "Shell command execution"),
    (r"child_process", "Node.js child process spawning"),
    (r"require\(['\"]child_process['\"]", "Child process module import"),
    (r"process\.env", "Environment variable access"),
    (r"\.ssh", "SSH directory access"),
    (r"id_rsa|id_ed25519", "SSH private key access"),
    (r"\.aws/credentials", "AWS credentials access"),
    (r"keychain|keystore", "Credential store access"),
    (r"\/etc\/passwd|\/etc\/shadow", "System password file access"),
    (r"base64\s*-d|atob\s*\(", "Base64 decoding (obfuscation)"),
    (r"String\.fromCharCode", "Char-code obfuscation"),
    (r"\\x[0-9a-fA-F]{2}", "Hex-encoded obfuscation"),
    (r"postinstall|preinstall|prepare", "Install lifecycle hook"),
    (r"npm install -g", "Global package install"),
    (r"pip install", "Python package install in script"),
    (r"crypto\.(createHash|randomBytes)", "Cryptographic operations"),
    (r"net\.connect|net\.createServer", "Raw network socket"),
    (r"https?:\/\/[^'\"]+\.(sh|py|exe|bat|ps1)", "Remote script download"),
]

# ── Suspicious npm Fields ──
SUSPICIOUS_NPM_FIELDS = [
    "postinstall", "preinstall", "install", "prepare",
    "postprepare", "preuninstall", "postuninstall"
]

findings = []
score = 0
_scan_lock = threading.Lock()
_GITHUB_AUTH_LOGGED = False

def log(level, msg, detail=""):
    icon = {"CRITICAL": f"{R}[CRITICAL]", "HIGH": f"{R}[HIGH]   ",
            "MEDIUM": f"{Y}[MEDIUM] ", "LOW": f"{Y}[LOW]    ",
            "INFO": f"{G}[INFO]   ", "PASS": f"{G}[PASS]   "}
    print(f"  {icon.get(level, '[???]')} {W}{msg}{RESET}")
    if detail:
        print(f"           {DIM}{detail}{RESET}")
    findings.append((level, msg))

def fetch_json(url):
    global _GITHUB_AUTH_LOGGED
    req_headers = {"User-Agent": "RepoScan/2.0"}
    if "api.github.com" in url:
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
            if not _GITHUB_AUTH_LOGGED:
                print(f"  {DIM}[INFO] Using authenticated GitHub API (5000 req/hr limit){RESET}")
                _GITHUB_AUTH_LOGGED = True
        else:
            if not _GITHUB_AUTH_LOGGED:
                print(f"  {Y}[WARN] No GITHUB_TOKEN set — GitHub API limited to 60 req/hr. Set env var for 5000 req/hr.{RESET}")
                _GITHUB_AUTH_LOGGED = True
    try:
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None

def fetch_text(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RepoScan-TM/2.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode(errors="replace")
    except Exception:
        return None

def check_prompt_injection(text, source=""):
    hits = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(pattern)
    return hits

def check_malicious_scripts(text):
    hits = []
    for pattern, desc in MALICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((pattern, desc))
    return hits

def section(title):
    print(f"\n{C}{BOLD}  ── {title} ──{RESET}")

def check_typosquat(package_name):
    """Check if package name looks like a typosquat of a popular package."""
    hits = []
    name_lower = package_name.lower().replace("-", "").replace("_", "")
    for popular in POPULAR_PACKAGES:
        pop_lower = popular.lower().replace("-", "").replace("_", "")
        if name_lower == pop_lower:
            continue  # exact match = it IS the package
        ratio = difflib.SequenceMatcher(None, name_lower, pop_lower).ratio()
        # Also check for common typosquat tricks
        if ratio >= 0.85 and abs(len(name_lower) - len(pop_lower)) <= 3:
            hits.append((popular, round(ratio * 100)))
        # Check for character substitution: lodash → l0dash, 1odash
        elif len(name_lower) == len(pop_lower) and ratio >= 0.80:
            hits.append((popular, round(ratio * 100)))
    return hits

# ══════════════════════════════════════════
#  NPM PACKAGE SCANNER
# ══════════════════════════════════════════
def scan_npm(package_name):
    global score
    version = None
    if "@" in package_name and not package_name.startswith("@"):
        parts = package_name.rsplit("@", 1)
        package_name, version = parts[0], parts[1]
    elif package_name.count("@") == 2:
        parts = package_name.rsplit("@", 1)
        package_name, version = parts[0], parts[1]

    print(f"\n{C}  Scanning npm package: {W}{BOLD}{package_name}{RESET}")
    if version:
        print(f"{C}  Version: {W}{version}{RESET}")

    # Fetch registry data
    data = fetch_json(f"https://registry.npmjs.org/{package_name}")
    if not data:
        log("HIGH", f"Could not fetch package from npm registry", "Package may not exist or registry is unreachable")
        return

    # ── Typosquat Detection ──
    section("Typosquat Detection")
    typo_hits = check_typosquat(package_name)
    if typo_hits:
        for (popular, similarity) in typo_hits[:3]:
            log("HIGH", f"Possible typosquat of '{popular}' ({similarity}% similar)",
                f"Is '{package_name}' a misspelling of '{popular}'? Verify carefully.")
            score += 35
    else:
        log("PASS", "No typosquat matches found against popular packages")

    # ── Basic Info ──
    section("Package Metadata")
    latest = data.get("dist-tags", {}).get("latest", "unknown")
    target_version = version or latest
    versions_list = list(data.get("versions", {}).keys())
    created = data.get("time", {}).get("created", "unknown")
    modified = data.get("time", {}).get("modified", "unknown")

    # Package age check — brand new packages are higher risk
    try:
        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        pkg_age_days = (datetime.now(timezone.utc) - created_dt).days
    except:
        pkg_age_days = 9999

    print(f"  {DIM}  Latest:    {latest}{RESET}")
    print(f"  {DIM}  Versions:  {len(versions_list)} total{RESET}")
    print(f"  {DIM}  Created:   {created[:10] if len(created)>9 else created} ({pkg_age_days} days ago){RESET}")
    print(f"  {DIM}  Modified:  {modified[:10] if len(modified)>9 else modified}{RESET}")

    if pkg_age_days < 30:
        log("HIGH", f"Package is only {pkg_age_days} days old — very new, minimal community vetting")
        score += 25
    elif pkg_age_days < 90:
        log("MEDIUM", f"Package is {pkg_age_days} days old — relatively new")
        score += 10
    else:
        log("PASS", f"Package age: {pkg_age_days} days — established")

    if len(versions_list) == 1:
        log("HIGH", "Only 1 version ever published — throwaway/attack package pattern")
        score += 30

    # ── Download count anomaly ──
    section("Download Stats")
    dl_data = fetch_json(f"https://api.npmjs.org/downloads/point/last-week/{package_name}")
    if dl_data:
        weekly_dl = dl_data.get("downloads", 0)
        print(f"  {DIM}  Downloads last 7 days: {weekly_dl:,}{RESET}")
        # New package + suddenly high downloads = coordinated install attack
        if pkg_age_days < 14 and weekly_dl > 1000:
            log("CRITICAL", f"ANOMALY: {weekly_dl:,} downloads in 7 days on a {pkg_age_days}-day-old package",
                "Coordinated install campaigns are a known supply chain attack pattern")
            score += 60
        elif weekly_dl == 0 and pkg_age_days > 30:
            log("LOW", "Zero downloads — unused/abandoned package")
        else:
            log("INFO", f"{weekly_dl:,} downloads/week")
    else:
        log("INFO", "Could not fetch download stats")

    # ── Check maintainers ──
    section("Maintainers & Account Age")
    maintainers = data.get("maintainers", [])
    if not maintainers:
        log("MEDIUM", "No maintainer info available")
        score += 10
    else:
        for m in maintainers:
            name = m.get('name', '?')
            email = m.get('email', '?')
            # Check maintainer profile for account age
            npm_profile = fetch_json(f"https://registry.npmjs.org/-/v1/search?text=maintainer:{name}&size=1")
            log("INFO", f"Maintainer: {name} <{email}>")

    # New maintainer on old established package = account takeover risk
    if len(versions_list) > 20 and len(maintainers) <= 1:
        log("MEDIUM", "Single maintainer on mature package — account takeover risk if maintainer changes")
        score += 10

    # ── Get version-specific data ──
    version_data = data.get("versions", {}).get(target_version, {})
    if not version_data:
        log("HIGH", f"Version {target_version} not found in registry")
        score += 20
        return

    # ── Check install scripts ──
    section("Install Scripts (Lifecycle Hooks)")
    scripts = version_data.get("scripts", {})
    if scripts:
        for hook in SUSPICIOUS_NPM_FIELDS:
            if hook in scripts:
                script_content = scripts[hook]
                log("HIGH", f"Lifecycle hook found: '{hook}'", script_content[:200])
                score += 30
                # Deep check the script content
                hits = check_malicious_scripts(script_content)
                for _, desc in hits:
                    log("CRITICAL", f"Malicious pattern in '{hook}': {desc}", script_content[:200])
                    score += 50
    else:
        log("PASS", "No lifecycle install scripts found")

    # ── Check dependencies ──
    section("Dependencies")
    deps = {**version_data.get("dependencies", {}), **version_data.get("devDependencies", {})}
    if len(deps) > 50:
        log("MEDIUM", f"Large dependency tree ({len(deps)} deps) — higher attack surface")
        score += 5
    else:
        log("INFO", f"{len(deps)} dependencies")

    # ── Check for obfuscation in dist ──
    section("Package Distribution")
    dist = version_data.get("dist", {})
    tarball = dist.get("tarball", "")
    shasum = dist.get("shasum", "")
    integrity = dist.get("integrity", "")

    if tarball:
        log("INFO", f"Tarball: {tarball}")
    if integrity:
        log("PASS", f"Integrity hash present: {integrity[:40]}...")
    else:
        log("MEDIUM", "No integrity hash — cannot verify package contents")
        score += 15

    # ── Version publish timing (recent = riskier) ──
    section("Version Timing")
    pub_time = data.get("time", {}).get(target_version, "")
    if pub_time:
        try:
            pub_dt = datetime.fromisoformat(pub_time.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - pub_dt).days
            print(f"  {DIM}  Published: {pub_time[:10]} ({age_days} days ago){RESET}")
            if age_days < 1:
                log("HIGH", "Package published LESS THAN 24 HOURS AGO — high risk window")
                score += 40
            elif age_days < 7:
                log("MEDIUM", f"Package published recently ({age_days} days ago)")
                score += 15
            else:
                log("PASS", f"Package age: {age_days} days")
        except:
            log("INFO", f"Published: {pub_time}")

    # ── GitHub Issues check (prompt injection) ──
    repo_url = version_data.get("repository", {})
    if isinstance(repo_url, dict):
        repo_url = repo_url.get("url", "")
    if repo_url:
        gh_match = re.search(r"github\.com[/:]([^/]+/[^/\.]+)", repo_url)
        if gh_match:
            scan_github_issues(gh_match.group(1))

def scan_github_issues(repo_slug):
    global score
    section(f"GitHub Issues — Prompt Injection Scan ({repo_slug})")
    issues_data = fetch_json(f"https://api.github.com/repos/{repo_slug}/issues?state=open&per_page=30")
    if not issues_data:
        log("INFO", "Could not fetch GitHub issues (API rate limit or private repo)")
        return

    injection_found = False
    for issue in issues_data:
        title = issue.get("title", "")
        body = issue.get("body", "") or ""
        url = issue.get("html_url", "")

        hits_title = check_prompt_injection(title)
        hits_body  = check_prompt_injection(body[:1000])

        # Title injection is CRITICAL — this is exactly the Cline attack vector
        # AI triage bots read issue titles as part of their context window
        if hits_title:
            log("CRITICAL",
                f"⚡ PROMPT INJECTION IN ISSUE TITLE #{issue['number']}",
                f"Title : \"{title[:120]}\"")
            print(f"           {R}Pattern: {hits_title[0]}{RESET}")
            print(f"           {R}URL    : {url}{RESET}")
            print(f"           {R}→ This is the exact Cline attack vector.{RESET}")
            print(f"           {R}  An AI triage bot reading this title could leak tokens.{RESET}")
            score += 80
            injection_found = True

        if hits_body:
            log("HIGH",
                f"Prompt injection in issue #{issue['number']} body",
                f"Title: \"{title[:80]}\"")
            print(f"           {Y}Pattern: {hits_body[0]}{RESET}")
            print(f"           {Y}URL    : {url}{RESET}")
            score += 40
            injection_found = True

    if not injection_found:
        log("PASS", f"No prompt injection patterns in {len(issues_data)} open issue titles/bodies")

    # ── Scan PR titles (also read by AI bots) ──
    pr_data = fetch_json(f"https://api.github.com/repos/{repo_slug}/pulls?state=open&per_page=20")
    if pr_data:
        pr_injection = False
        for pr in pr_data:
            title = pr.get("title", "")
            body  = pr.get("body", "") or ""
            url   = pr.get("html_url", "")
            hits_title = check_prompt_injection(title)
            hits_body  = check_prompt_injection(body[:500])
            if hits_title:
                log("CRITICAL",
                    f"⚡ PROMPT INJECTION IN PR TITLE #{pr['number']}",
                    f"Title: \"{title[:120]}\"")
                print(f"           {R}Pattern: {hits_title[0]}{RESET}")
                print(f"           {R}URL    : {url}{RESET}")
                score += 80
                pr_injection = True
            if hits_body:
                log("HIGH", f"Prompt injection in PR #{pr['number']} body",
                    f"Title: \"{title[:80]}\"")
                score += 40
                pr_injection = True
        if not pr_injection:
            log("PASS", f"No prompt injection in {len(pr_data)} open PR titles")

    # ── Scan recent issue comments (attackers hide injection in comments too) ──
    comments_data = fetch_json(f"https://api.github.com/repos/{repo_slug}/issues/comments?per_page=20&sort=created&direction=desc")
    if comments_data:
        comment_injection = False
        for comment in comments_data:
            body = comment.get("body", "") or ""
            url  = comment.get("html_url", "")
            hits = check_prompt_injection(body[:500])
            if hits:
                log("HIGH",
                    f"Prompt injection in recent issue comment",
                    f"URL: {url}")
                print(f"           {Y}Pattern: {hits[0]}{RESET}")
                score += 35
                comment_injection = True
        if not comment_injection:
            log("PASS", f"No prompt injection in {len(comments_data)} recent comments")

# ══════════════════════════════════════════
#  GITHUB REPO SCANNER
# ══════════════════════════════════════════
def scan_github_repo(repo_slug):
    global score
    print(f"\n{C}  Scanning GitHub repo: {W}{BOLD}{repo_slug}{RESET}")

    # ── Repo metadata ──
    section("Repository Info")
    repo_data = fetch_json(f"https://api.github.com/repos/{repo_slug}")
    if not repo_data:
        log("HIGH", "Could not fetch repo data — may be private or invalid")
        return

    print(f"  {DIM}  Stars:       {repo_data.get('stargazers_count', 0)}{RESET}")
    print(f"  {DIM}  Forks:       {repo_data.get('forks_count', 0)}{RESET}")
    print(f"  {DIM}  Created:     {str(repo_data.get('created_at',''))[:10]}{RESET}")
    print(f"  {DIM}  Last push:   {str(repo_data.get('pushed_at',''))[:10]}{RESET}")
    print(f"  {DIM}  Language:    {repo_data.get('language','?')}{RESET}")

    stars = repo_data.get("stargazers_count", 0)
    if stars < 10:
        log("MEDIUM", f"Low star count ({stars}) — less community vetting")
        score += 10

    # ── Check package.json if JS repo ──
    section("package.json Analysis")
    pkg_content = fetch_text(f"https://raw.githubusercontent.com/{repo_slug}/main/package.json")
    if not pkg_content:
        pkg_content = fetch_text(f"https://raw.githubusercontent.com/{repo_slug}/master/package.json")

    if pkg_content:
        try:
            pkg = json.loads(pkg_content)
            scripts = pkg.get("scripts", {})
            for hook in SUSPICIOUS_NPM_FIELDS:
                if hook in scripts:
                    val = scripts[hook]
                    log("HIGH", f"Install hook in package.json: '{hook}'", val[:200])
                    score += 30
                    hits = check_malicious_scripts(val)
                    for _, desc in hits:
                        log("CRITICAL", f"Dangerous pattern in hook '{hook}': {desc}")
                        score += 50
            if not any(h in scripts for h in SUSPICIOUS_NPM_FIELDS):
                log("PASS", "No suspicious install hooks in package.json")
        except json.JSONDecodeError:
            log("MEDIUM", "package.json is not valid JSON")
            score += 10
    else:
        log("INFO", "No package.json found (not a Node.js project)")

    # ── Check common CI/workflow files for injections ──
    section("CI/Workflow Files")
    workflow_paths = [
        ".github/workflows/ci.yml", ".github/workflows/main.yml",
        ".github/workflows/publish.yml", ".github/workflows/release.yml",
    ]
    workflow_found = False
    for wf_path in workflow_paths:
        content = fetch_text(f"https://raw.githubusercontent.com/{repo_slug}/main/{wf_path}")
        if content:
            workflow_found = True
            hits = check_malicious_scripts(content)
            inj = check_prompt_injection(content)
            if hits:
                for _, desc in hits:
                    log("HIGH", f"Suspicious pattern in {wf_path}: {desc}")
                    score += 25
            if inj:
                log("CRITICAL", f"Prompt injection pattern in {wf_path}")
                score += 50
            if not hits and not inj:
                log("PASS", f"Workflow clean: {wf_path}")

    if not workflow_found:
        log("INFO", "No common workflow files found")

    # ── Scan open issues for prompt injection ──
    scan_github_issues(repo_slug)

    # ── Check README for red flags ──
    section("README Scan")
    readme = fetch_text(f"https://raw.githubusercontent.com/{repo_slug}/main/README.md")
    if not readme:
        readme = fetch_text(f"https://raw.githubusercontent.com/{repo_slug}/master/README.md")
    if readme:
        inj = check_prompt_injection(readme[:2000])
        ms = check_malicious_scripts(readme[:2000])
        if inj:
            log("HIGH", "Prompt injection pattern found in README")
            score += 20
        if ms:
            for _, desc in ms:
                log("MEDIUM", f"Suspicious pattern in README: {desc}")
                score += 10
        if not inj and not ms:
            log("PASS", "README appears clean")
    else:
        log("INFO", "Could not fetch README")

# ══════════════════════════════════════════
#  VERDICT
# ══════════════════════════════════════════
def print_verdict():
    global score
    print(f"\n{C}{BOLD}{'═'*60}{RESET}")
    print(f"{C}{BOLD}  SCAN VERDICT{RESET}")
    print(f"{C}{BOLD}{'═'*60}{RESET}")

    criticals = sum(1 for f in findings if f[0] == "CRITICAL")
    highs     = sum(1 for f in findings if f[0] == "HIGH")
    mediums   = sum(1 for f in findings if f[0] == "MEDIUM")
    passes    = sum(1 for f in findings if f[0] == "PASS")

    print(f"\n  {R}Critical: {criticals}  {R}High: {highs}  {Y}Medium: {mediums}  {G}Pass: {passes}{RESET}")
    print(f"  Risk Score: {BOLD}{score}{RESET}\n")

    if criticals > 0 or score >= 80:
        print(f"  {R}{BOLD}⛔  DO NOT INSTALL — HIGH RISK DETECTED{RESET}")
        print(f"  {R}Critical indicators found. This package/repo shows signs of{RESET}")
        print(f"  {R}malicious activity or prompt injection attacks.{RESET}")
    elif highs > 0 or score >= 40:
        print(f"  {Y}{BOLD}⚠️  PROCEED WITH CAUTION{RESET}")
        print(f"  {Y}High-risk patterns detected. Review findings above carefully{RESET}")
        print(f"  {Y}before installing. Consider sandboxing first.{RESET}")
    elif mediums > 0 or score >= 15:
        print(f"  {Y}{BOLD}🔍  LOW-MEDIUM RISK — REVIEW RECOMMENDED{RESET}")
        print(f"  {Y}Some patterns worth reviewing. Generally likely safe.{RESET}")
    else:
        print(f"  {G}{BOLD}✅  APPEARS SAFE{RESET}")
        print(f"  {G}No critical indicators found. Normal precautions apply.{RESET}")

    print(f"\n  {DIM}Note: This scanner checks known patterns. It cannot guarantee{RESET}")
    print(f"  {DIM}safety. Always review source code for critical installs.{RESET}")
    print(f"\n{C}{'═'*60}{RESET}")
    print(f"\n{C}{BOLD}  Want deeper protection?{RESET}")
    print(f"  {W}ShieldStack™{RESET} — Continuous repo monitoring, tarball inspection,")
    print(f"  PyPI/Docker/RubyGems scanning, alerts & dashboard.")
    print(f"  {C}→ https://shieldstack.netlify.app{RESET}")
    print(f"\n  {DIM}RepoScan™ is free forever. Built by CW Affiliate Investments LLC.{RESET}")
    print(f"  {DIM}GitHub: https://github.com/cwinvestments/reposcan{RESET}")
    print(f"\n{C}{'═'*60}{RESET}\n")

# ══════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════
def run_scan_capture(target: str) -> dict:
    """Thread-safe scan wrapper. Both CLI and Flask call this.
    Resets globals, runs scan, captures stdout, runs verdict, returns structured result."""
    global score, _GITHUB_AUTH_LOGGED
    import io, contextlib
    buf = io.StringIO()
    with _scan_lock:
        findings.clear()
        score = 0
        _GITHUB_AUTH_LOGGED = False
        with contextlib.redirect_stdout(buf):
            if target.startswith("github:"):
                scan_github_repo(target[7:])
            else:
                scan_npm(target)
            print_verdict()
        # snapshot under lock
        result = {
            "target": target,
            "findings": list(findings),
            "score": score,
            "raw_output": buf.getvalue(),
        }
    return result

def main():
    # Windows default stdout encoding is cp1252, which cannot encode the Unicode
    # box-drawing characters in BANNER. Reconfigure to UTF-8 so piped output works.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target", nargs="?")
    parser.add_argument("--ui", action="store_true")
    parser.add_argument("--ui-port", type=int, default=5000)
    parser.add_argument("--ui-host", default="127.0.0.1")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.ui:
        from reposcan_ui import run_ui
        run_ui(host=args.ui_host, port=args.ui_port)
        return

    print(BANNER)

    if args.help or not args.target:
        print(f"  {W}Usage:{RESET}")
        print(f"    python reposcan.py <npm-package>          # npm package")
        print(f"    python reposcan.py <npm-package@version>  # specific version")
        print(f"    python reposcan.py github:<owner/repo>    # GitHub repo")
        print(f"\n  {W}Examples:{RESET}")
        print(f"    python reposcan.py cline")
        print(f"    python reposcan.py cline@2.3.0")
        print(f"    python reposcan.py github:clinetools/cline\n")
        sys.exit(0)

    target = args.target
    print(f"  {DIM}Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    if target.startswith("github:"):
        scan_github_repo(target[7:])
    else:
        scan_npm(target)

    print_verdict()

if __name__ == "__main__":
    main()
# ── PATCH: add this to end of file for testing ──
