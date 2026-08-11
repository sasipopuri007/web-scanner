from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from pathlib import Path
from urllib.parse import urlparse
import subprocess
import sqlite3
from datetime import datetime

app = FastAPI(title="Web Vulnerability Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
SCANNER_DIR = BASE_DIR / "scanner"
PYTHON = SCANNER_DIR / ".venv" / "Scripts" / "python.exe"
SCAN_FILE = SCANNER_DIR / "scan.py"
DB = BASE_DIR / "data" / "scanner.db"

DB.parent.mkdir(parents=True, exist_ok=True)


def init_db():
    conn = sqlite3.connect(DB)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            output TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


class ScanRequest(BaseModel):
    target: HttpUrl


def allowed_target(target: str) -> bool:
    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.hostname:
        return False

    return True


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def start_scan(request: ScanRequest):

    target = str(request.target).rstrip("/")

    if not allowed_target(target):
        raise HTTPException(
            status_code=400,
            detail="Only HTTP and HTTPS URLs are allowed."
        )

    if not PYTHON.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Scanner Python not found: {PYTHON}"
        )

    if not SCAN_FILE.exists():
        raise HTTPException(
            status_code=500,
            detail=f"scan.py not found: {SCAN_FILE}"
        )

    started = datetime.now().isoformat()

    conn = sqlite3.connect(DB)

    cursor = conn.execute(
        """
        INSERT INTO scans
        (target, status, started_at)
        VALUES (?, ?, ?)
        """,
        (target, "RUNNING", started)
    )

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    try:

        command = [
            str(PYTHON),
            str(SCAN_FILE),
            "--url",
            target,
            "--max-pages",
            "15",
            "--n",
            "15"
        ]

        result = subprocess.run(
            command,
            cwd=SCANNER_DIR,
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout

        if result.stderr:
            output += "\n\nERROR OUTPUT:\n" + result.stderr

        status = (
            "COMPLETED"
            if result.returncode == 0
            else "FAILED"
        )

    except subprocess.TimeoutExpired:

        output = "Scan timed out after 300 seconds."
        status = "TIMEOUT"

    except Exception as error:

        output = str(error)
        status = "FAILED"

    completed = datetime.now().isoformat()

    conn = sqlite3.connect(DB)

    conn.execute(
        """
        UPDATE scans
        SET status = ?,
            completed_at = ?,
            output = ?
        WHERE id = ?
        """,
        (
            status,
            completed,
            output,
            scan_id
        )
    )

    conn.commit()
    conn.close()

    return {
        "scan_id": scan_id,
        "target": target,
        "status": status,
        "output": output
    }


@app.get("/scans")
def get_scans():

    conn = sqlite3.connect(DB)

    rows = conn.execute(
        """
        SELECT
            id,
            target,
            status,
            started_at,
            completed_at
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return [
        {
            "id": row[0],
            "target": row[1],
            "status": row[2],
            "started_at": row[3],
            "completed_at": row[4]
        }
        for row in rows
    ]


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):

    conn = sqlite3.connect(DB)

    row = conn.execute(
        """
        SELECT
            id,
            target,
            status,
            started_at,
            completed_at,
            output
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    conn.close()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    return {
        "id": row[0],
        "target": row[1],
        "status": row[2],
        "started_at": row[3],
        "completed_at": row[4],
        "output": row[5]
    }
