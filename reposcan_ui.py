"""RepoScan Web UI — Flask wrapper around reposcan.run_scan_capture.

CLI logic in reposcan.py is not touched. This module only consumes
`run_scan_capture(target) -> dict` and presents results in a browser.
"""
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
from datetime import datetime

from flask import (Flask, abort, g, redirect, render_template, request,
                   Response, url_for)

import reposcan

# ── paths ──
HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "scans.db")

# ── ANSI stripping (helper lives here, NOT in reposcan.py) ──
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

def finding_hash(level: str, msg: str) -> str:
    return hashlib.sha256(f"{level}|{msg}".encode("utf-8")).hexdigest()[:16]

def compute_verdict(findings, score):
    crit = sum(1 for lvl, _ in findings if lvl == "CRITICAL")
    high = sum(1 for lvl, _ in findings if lvl == "HIGH")
    med  = sum(1 for lvl, _ in findings if lvl == "MEDIUM")
    if crit > 0 or score >= 80:
        return "DO NOT INSTALL", "danger"
    if high > 0 or score >= 40:
        return "PROCEED WITH CAUTION", "warning"
    if med > 0 or score >= 15:
        return "LOW-MEDIUM RISK — REVIEW RECOMMENDED", "notice"
    return "APPEARS SAFE", "safe"

RATE_LIMIT_SIGNALS = (
    "API rate limit",
    "Could not fetch GitHub issues",
    "Could not fetch repo data",
)

def detect_rate_limit(raw_output: str) -> bool:
    if not raw_output:
        return False
    return any(sig in raw_output for sig in RATE_LIMIT_SIGNALS)

# ── DB ──
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT    NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    score          INTEGER NOT NULL,
    verdict        TEXT    NOT NULL,
    verdict_class  TEXT    NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    medium_count   INTEGER NOT NULL DEFAULT 0,
    low_count      INTEGER NOT NULL DEFAULT 0,
    info_count     INTEGER NOT NULL DEFAULT 0,
    pass_count     INTEGER NOT NULL DEFAULT 0,
    findings_json  TEXT    NOT NULL,
    full_output    TEXT    NOT NULL,
    rate_limit_hit INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dismissed_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    finding_hash  TEXT    NOT NULL,
    reason        TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target, finding_hash)
);
CREATE INDEX IF NOT EXISTS idx_scans_target  ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dismissed_target ON dismissed_findings(target);
"""

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()

# ── app factory ──
app = Flask(__name__, template_folder=os.path.join(HERE, "templates"),
                      static_folder=os.path.join(HERE, "static"))

@app.teardown_appcontext
def _close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

@app.context_processor
def _inject_globals():
    banner = strip_ansi(reposcan.BANNER).strip("\n")
    return {"BANNER_PLAIN": banner}

# ── routes ──
@app.get("/")
def index():
    db = get_db()
    rows = db.execute(
        "SELECT id, target, created_at, score, verdict, verdict_class "
        "FROM scans ORDER BY id DESC LIMIT 10"
    ).fetchall()
    return render_template("index.html", recent=rows)

@app.post("/scan")
def scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        return redirect(url_for("index"))

    result = reposcan.run_scan_capture(target)
    clean_output = strip_ansi(result["raw_output"])
    findings = result["findings"]
    score = result["score"]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "PASS": 0}
    for lvl, _ in findings:
        counts[lvl] = counts.get(lvl, 0) + 1

    verdict, vclass = compute_verdict(findings, score)
    rate_limit_hit = 1 if detect_rate_limit(clean_output) else 0

    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (target, score, verdict, verdict_class, "
        "critical_count, high_count, medium_count, low_count, info_count, pass_count, "
        "findings_json, full_output, rate_limit_hit) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target, score, verdict, vclass,
         counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
         counts["INFO"], counts["PASS"],
         json.dumps(findings), clean_output, rate_limit_hit),
    )
    db.commit()
    return redirect(url_for("results", scan_id=cur.lastrowid))

def _load_scan(scan_id):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        abort(404)
    return row

def _load_dismissed(target):
    db = get_db()
    rows = db.execute(
        "SELECT finding_hash, reason FROM dismissed_findings WHERE target = ?",
        (target,),
    ).fetchall()
    return {r["finding_hash"]: r["reason"] for r in rows}

def _group_findings(findings_list, dismissed_map):
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": [], "PASS": []}
    for lvl, msg in findings_list:
        h = finding_hash(lvl, msg)
        groups.setdefault(lvl, []).append({
            "level": lvl,
            "msg": msg,
            "hash": h,
            "dismissed": h in dismissed_map,
            "dismiss_reason": dismissed_map.get(h, ""),
        })
    return groups

@app.get("/results/<int:scan_id>")
def results(scan_id):
    row = _load_scan(scan_id)
    findings_list = json.loads(row["findings_json"])
    dismissed = _load_dismissed(row["target"])
    groups = _group_findings(findings_list, dismissed)
    return render_template("results.html",
        scan=row, groups=groups, findings=findings_list,
        dismissed=dismissed, readonly=False,
    )

@app.post("/dismiss/<int:scan_id>")
def dismiss(scan_id):
    row = _load_scan(scan_id)
    fhash = (request.form.get("finding_hash") or "").strip()
    reason = (request.form.get("reason") or "").strip()
    if not fhash:
        return redirect(url_for("results", scan_id=scan_id))
    db = get_db()
    try:
        db.execute(
            "INSERT INTO dismissed_findings (target, finding_hash, reason) VALUES (?, ?, ?)",
            (row["target"], fhash, reason),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Already dismissed; update reason
        db.execute(
            "UPDATE dismissed_findings SET reason = ? WHERE target = ? AND finding_hash = ?",
            (reason, row["target"], fhash),
        )
        db.commit()
    return redirect(url_for("results", scan_id=scan_id))

@app.get("/history")
def history():
    q = (request.args.get("q") or "").strip()
    sort = (request.args.get("sort") or "recent").strip()
    order_sql = {
        "recent":  "id DESC",
        "oldest":  "id ASC",
        "score":   "score DESC, id DESC",
        "target":  "target ASC, id DESC",
    }.get(sort, "id DESC")

    db = get_db()
    if q:
        rows = db.execute(
            f"SELECT id, target, created_at, score, verdict, verdict_class "
            f"FROM scans WHERE target LIKE ? ORDER BY {order_sql}",
            (f"%{q}%",),
        ).fetchall()
    else:
        rows = db.execute(
            f"SELECT id, target, created_at, score, verdict, verdict_class "
            f"FROM scans ORDER BY {order_sql}"
        ).fetchall()
    return render_template("history.html", scans=rows, q=q, sort=sort)

@app.get("/history.csv")
def history_csv():
    db = get_db()
    rows = db.execute(
        "SELECT id, target, created_at, score, verdict, "
        "critical_count, high_count, medium_count, low_count, pass_count "
        "FROM scans ORDER BY id DESC"
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "target", "created_at", "score", "verdict",
                "critical", "high", "medium", "low", "pass"])
    for r in rows:
        w.writerow([r["id"], r["target"], r["created_at"], r["score"], r["verdict"],
                    r["critical_count"], r["high_count"], r["medium_count"],
                    r["low_count"], r["pass_count"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=reposcan-history.csv"})

@app.get("/share/<int:scan_id>")
def share(scan_id):
    row = _load_scan(scan_id)
    findings_list = json.loads(row["findings_json"])
    dismissed = _load_dismissed(row["target"])
    groups = _group_findings(findings_list, dismissed)
    return render_template("share.html",
        scan=row, groups=groups, findings=findings_list,
        dismissed=dismissed, readonly=True,
    )

@app.post("/rescan/<int:scan_id>")
def rescan(scan_id):
    row = _load_scan(scan_id)
    target = row["target"]
    # Re-run scan via the same code path as /scan
    result = reposcan.run_scan_capture(target)
    clean_output = strip_ansi(result["raw_output"])
    findings = result["findings"]
    score = result["score"]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "PASS": 0}
    for lvl, _ in findings:
        counts[lvl] = counts.get(lvl, 0) + 1

    verdict, vclass = compute_verdict(findings, score)
    rate_limit_hit = 1 if detect_rate_limit(clean_output) else 0

    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (target, score, verdict, verdict_class, "
        "critical_count, high_count, medium_count, low_count, info_count, pass_count, "
        "findings_json, full_output, rate_limit_hit) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target, score, verdict, vclass,
         counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
         counts["INFO"], counts["PASS"],
         json.dumps(findings), clean_output, rate_limit_hit),
    )
    db.commit()
    return redirect(url_for("results", scan_id=cur.lastrowid))

# ── entry point ──
def run_ui(host: str = "127.0.0.1", port: int = 5000) -> None:
    init_db()
    print(f"RepoScan UI → http://{host}:{port}")
    app.run(host=host, port=port, threaded=True, debug=False)

# Ensure DB exists when imported (e.g. by test_client)
init_db()
