from datetime import datetime
import hashlib
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import mysql.connector
from pydantic import BaseModel

app = FastAPI(title="Cyber Forensics DBMS")

# Resolve static directory path reliably for both local and Vercel serverless environments
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def get_db():
  return mysql.connector.connect(
      host=os.environ.get("DB_HOST", "localhost"),
      port=int(os.environ.get("DB_PORT", 3306)),
      user=os.environ.get("DB_USER", "avnadmin"),
      password=os.environ.get("DB_PASSWORD", ""),
      database=os.environ.get("DB_NAME", "defaultdb"),
      ssl_disabled=False,
  )


class LogCreate(BaseModel):
  host_id: int
  event_type: str
  source_ip: str
  raw_payload: str
  role: str = "root"


class TamperRequest(BaseModel):
  log_id: int
  fake_payload: str
  role: str = "root"


class CloseIncidentRequest(BaseModel):
  incident_id: int
  role: str = "root"


@app.get("/")
def serve_ui():
  return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/dashboard")
def get_dashboard_data(incident_id: int = 1):
  conn = get_db()
  cursor = conn.cursor(dictionary=True)

  cursor.execute("""
        SELECT 
            (SELECT COUNT(*) FROM incidents) AS total_incidents,
            (SELECT COUNT(*) FROM incidents WHERE status != 'Closed') AS active_incidents,
            (SELECT COUNT(*) FROM compromised_hosts) AS total_hosts,
            (SELECT COUNT(*) FROM forensic_logs) AS total_logs,
            (SELECT COUNT(*) FROM custody_audit) AS audit_entries
    """)
  stats = cursor.fetchone()

  cursor.execute("""
        SELECT incident_id, title, severity, status,
               CAST(detected_at AS CHAR) AS detected_at,
               lead_investigator_id
        FROM incidents ORDER BY incident_id ASC
    """)
  incidents = cursor.fetchall()

  cursor.execute(
      "SELECT host_id, hostname, ip_address, incident_id FROM compromised_hosts"
  )
  hosts = cursor.fetchall()

  cursor.execute(
      """
        SELECT fl.log_id, CAST(fl.event_timestamp AS CHAR) AS event_timestamp,
               ch.hostname, ch.ip_address AS host_ip, fl.event_type, fl.source_ip,
               fl.raw_payload, LEFT(fl.sha256_hash, 16) AS short_hash
        FROM forensic_logs fl
        JOIN compromised_hosts ch ON fl.host_id = ch.host_id
        WHERE ch.incident_id = %s
        ORDER BY fl.event_timestamp ASC
    """,
      (incident_id,),
  )
  timeline = cursor.fetchall()

  cursor.execute("""
        SELECT audit_id, log_id, action_type, performed_by,
               CAST(action_timestamp AS CHAR) AS action_timestamp
        FROM custody_audit ORDER BY audit_id DESC LIMIT 12
    """)
  audits = cursor.fetchall()

  cursor.execute("""
        SELECT inv.full_name, inv.clearance_level,
               COUNT(i.incident_id) AS total_cases,
               CAST(COALESCE(SUM(CASE WHEN i.severity = 'Critical' THEN 1 ELSE 0 END), 0) AS SIGNED) AS critical_cases
        FROM investigators inv
        LEFT JOIN incidents i ON inv.investigator_id = i.lead_investigator_id
        GROUP BY inv.investigator_id, inv.full_name, inv.clearance_level
    """)
  workload = cursor.fetchall()

  cursor.execute("""
        EXPLAIN SELECT * FROM forensic_logs 
        WHERE host_id = 1 AND event_timestamp BETWEEN '2026-11-01 00:00:00' AND '2026-11-30 23:59:59'
    """)
  explain_plan = cursor.fetchall()

  cursor.close()
  conn.close()
  return {
      "stats": stats,
      "incidents": incidents,
      "hosts": hosts,
      "timeline": timeline,
      "audits": audits,
      "workload": workload,
      "explain": explain_plan,
  }


@app.post("/api/logs")
def ingest_log(data: LogCreate):
  conn = get_db()
  cursor = conn.cursor()
  try:
    sha_hash = hashlib.sha256(data.raw_payload.encode("utf-8")).hexdigest()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    cursor.execute(
        """
            INSERT INTO forensic_logs (host_id, event_timestamp, event_type, source_ip, raw_payload, sha256_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            data.host_id,
            now,
            data.event_type,
            data.source_ip,
            data.raw_payload,
            sha_hash,
        ),
    )
    conn.commit()
    return {
        "message": (
            "Log ingested! MySQL Trigger (trg_after_log_insert) logged"
            " chain-of-custody."
        )
    }
  except mysql.connector.Error as err:
    conn.rollback()
    raise HTTPException(status_code=400, detail=err.msg)
  finally:
    cursor.close()
    conn.close()


@app.post("/api/tamper")
def test_tamper(data: TamperRequest):
  if data.role == "analyst_user":
    raise HTTPException(
        status_code=403,
        detail=(
            "UPDATE command denied to user 'analyst_user'@'localhost' for"
            " table 'forensic_logs' (RBAC Policy)"
        ),
    )
  conn = get_db()
  cursor = conn.cursor()
  try:
    cursor.execute(
        "UPDATE forensic_logs SET raw_payload = %s WHERE log_id = %s",
        (data.fake_payload, data.log_id),
    )
    conn.commit()
    return {"message": "Update succeeded."}
  except mysql.connector.Error as err:
    conn.rollback()
    raise HTTPException(status_code=403, detail=err.msg)
  finally:
    cursor.close()
    conn.close()


@app.post("/api/close-incident")
def close_incident(data: CloseIncidentRequest):
  if data.role == "analyst_user":
    raise HTTPException(
        status_code=403,
        detail=(
            "EXECUTE command denied to user 'analyst_user'@'localhost' for"
            " procedure 'sp_close_incident' (RBAC Policy)"
        ),
    )
  conn = get_db()
  cursor = conn.cursor()
  try:
    args = cursor.callproc("sp_close_incident", [data.incident_id, ""])
    conn.commit()
    return {"message": args[1]}
  except mysql.connector.Error as err:
    conn.rollback()
    raise HTTPException(status_code=403, detail=err.msg)
  finally:
    cursor.close()
    conn.close()