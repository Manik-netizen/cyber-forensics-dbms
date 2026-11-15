# from datetime import datetime
# import hashlib
# import mysql.connector
# import pandas as pd
# import streamlit as st

# st.set_page_config(page_title="Cyber Forensics DBMS", layout="wide")


# # --- DATABASE CONNECTION ---
# def get_connection():
#   return mysql.connector.connect(
#       host="localhost",
#       user="root",  # Use 'analyst_user' to demonstrate RBAC restrictions
#       password="root",
#       database="cyber_forensics_db",
#   )


# def run_query(query, params=None):
#   conn = get_connection()
#   df = pd.read_sql(query, conn, params=params)
#   conn.close()
#   return df


# st.title("Cyber Forensics & Incident Log Management System")
# st.caption(
#     "B.Tech DBMS Mini-Project | MySQL 8.0 + Python (Triggers, Stored"
#     " Procedures, Indexing & RBAC)  \n**Manik Dewan | J250210085 | 2nd Year"
#     " (B.Tech CSE)**"
# )

# tab1, tab2, tab3, tab4 = st.tabs([
#     "1. Attack Timeline (Joins)",
#     "2. Ingest Evidence & Trigger Audit",
#     "3. Tamper Test & Stored Procedure",
#     "4. Analytics & EXPLAIN Plan",
# ])

# # ==========================================
# # TAB 1: CHRONOLOGICAL TIMELINE RECONSTRUCTION
# # ==========================================
# with tab1:
#   st.subheader("Incident Attack Timeline Reconstruction")
#   incidents_df = run_query(
#       "SELECT incident_id, title, severity, status FROM incidents"
#   )

#   selected_inc = st.selectbox(
#       "Select Incident Case",
#       options=incidents_df["incident_id"].tolist(),
#       format_func=lambda x: (
#           f"#{x} -"
#           f" {incidents_df.loc[incidents_df['incident_id']==x, 'title'].values[0]}"
#           f" ({incidents_df.loc[incidents_df['incident_id']==x, 'status'].values[0]})"
#       ),
#   )

#   timeline_query = """
#         SELECT fl.log_id, fl.event_timestamp, ch.hostname, ch.ip_address AS host_ip,
#                fl.event_type, fl.source_ip, fl.raw_payload, LEFT(fl.sha256_hash, 16) AS short_hash
#         FROM forensic_logs fl
#         JOIN compromised_hosts ch ON fl.host_id = ch.host_id
#         WHERE ch.incident_id = %s
#         ORDER BY fl.event_timestamp ASC
#     """
#   timeline_df = run_query(timeline_query, params=(selected_inc,))
#   st.dataframe(timeline_df, use_container_width=True)

# # ==========================================
# # TAB 2: INGEST LOGS + LIVE TRIGGER DEMO
# # ==========================================
# with tab2:
#   col1, col2 = st.columns([1, 1])

#   with col1:
#     st.subheader("Ingest New Forensic Log")
#     hosts_df = run_query(
#         "SELECT host_id, hostname, incident_id FROM compromised_hosts"
#     )
#     host_id = st.selectbox(
#         "Target Compromised Host",
#         options=hosts_df["host_id"].tolist(),
#         format_func=lambda x: (
#             f"Host #{x}:"
#             f" {hosts_df.loc[hosts_df['host_id']==x, 'hostname'].values[0]}"
#             f" (Incident #{hosts_df.loc[hosts_df['host_id']==x, 'incident_id'].values[0]})"
#         ),
#     )
#     event_type = st.selectbox(
#         "Event Type",
#         [
#             "FAILED_SSH_LOGIN",
#             "MALWARE_DROP",
#             "PRIVILEGE_ESCALATION",
#             "OUTBOUND_C2_BEACON",
#         ],
#     )
#     source_ip = st.text_input("Source IP Address", value="192.168.1.105")
#     raw_payload = st.text_area(
#         "Raw Log Payload",
#         value="Unauthorized sudo execution attempt by user www-data",
#     )

#     if st.button("Insert Log into MySQL", type="primary"):
#       conn = get_connection()
#       cursor = conn.cursor()
#       try:
#         sha_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
#         now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
#         sql = """
#                     INSERT INTO forensic_logs (host_id, event_timestamp, event_type, source_ip, raw_payload, sha256_hash)
#                     VALUES (%s, %s, %s, %s, %s, %s)
#                 """
#         cursor.execute(
#             sql, (host_id, now, event_type, source_ip, raw_payload, sha_hash)
#         )
#         conn.commit()
#         st.success(
#             "Log inserted! `trg_after_log_insert` automatically recorded the"
#             " chain-of-custody entry."
#         )
#       except mysql.connector.Error as e:
#         st.error(f"MySQL Error: {e}")
#       finally:
#         cursor.close()
#         conn.close()

#   with col2:
#     st.subheader("Live Chain-of-Custody Audit (`custody_audit`)")
#     st.caption(
#         "Populated automatically by MySQL AFTER INSERT trigger — never written"
#         " directly by Python."
#     )
#     audit_df = run_query(
#         "SELECT * FROM custody_audit ORDER BY audit_id DESC LIMIT 10"
#     )
#     st.dataframe(audit_df, use_container_width=True)

# # ==========================================
# # TAB 3: TRIGGER TAMPER TEST & STORED PROCEDURE
# # ==========================================
# with tab3:
#   c1, c2 = st.columns(2)

#   with c1:
#     st.subheader("1. Test Immutability Trigger (`BEFORE UPDATE`)")
#     st.write(
#         "Attempt to alter an existing log payload to prove the database blocks"
#         " tampering:"
#     )
#     tamper_log_id = st.number_input("Log ID to Modify", min_value=1, value=1)
#     fake_payload = st.text_input(
#         "Altered Payload Text", value="Normal authorized login"
#     )

#     if st.button("Attempt Unauthorized Update"):
#       conn = get_connection()
#       cursor = conn.cursor()
#       try:
#         cursor.execute(
#             "UPDATE forensic_logs SET raw_payload = %s WHERE log_id = %s",
#             (fake_payload, tamper_log_id),
#         )
#         conn.commit()
#         st.warning("Updated (unexpected).")
#       except mysql.connector.Error as err:
#         st.error(f"Blocked by MySQL Trigger: {err.msg}")
#       finally:
#         cursor.close()
#         conn.close()

#   with c2:
#     st.subheader("2. Execute Stored Procedure (`sp_close_incident`)")
#     st.write(
#         "Closes an incident inside a transaction only if verified logs exist:"
#     )
#     proc_inc_id = st.number_input("Incident ID to Close", min_value=1, value=1)

#     if st.button("Call sp_close_incident"):
#       conn = get_connection()
#       cursor = conn.cursor()
#       try:
#         # Call MySQL Stored Procedure with IN and OUT parameters
#         args = cursor.callproc("sp_close_incident", [proc_inc_id, ""])
#         conn.commit()
#         st.info(f"Stored Procedure Output: **{args[1]}**")
#       except mysql.connector.Error as err:
#         st.error(f"Error: {err.msg}")
#       finally:
#         cursor.close()
#         conn.close()

# # ==========================================
# # TAB 4: REPORT QUERIES & INDEX OPTIMIZATION
# # ==========================================
# with tab4:
#   st.subheader("Investigator Workload Aggregation (`GROUP BY`)")
#   workload_df = run_query("""
#         SELECT inv.full_name AS Investigator, inv.clearance_level AS Clearance,
#                COUNT(i.incident_id) AS Total_Cases,
#                SUM(CASE WHEN i.severity = 'Critical' THEN 1 ELSE 0 END) AS Critical_Cases
#         FROM investigators inv
#         LEFT JOIN incidents i ON inv.investigator_id = i.lead_investigator_id
#         GROUP BY inv.investigator_id, inv.full_name, inv.clearance_level
#     """)
#   st.dataframe(workload_df, use_container_width=True)

#   st.subheader("Query Performance Proof (`EXPLAIN` Composite Index)")
#   explain_df = run_query("""
#         EXPLAIN SELECT * FROM forensic_logs 
#         WHERE host_id = 1 AND event_timestamp BETWEEN '2026-11-01 00:00:00' AND '2026-11-30 23:59:59'
#     """)
#   st.dataframe(explain_df, use_container_width=True)

from datetime import datetime
import hashlib
import mysql.connector
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Cyber Forensics DBMS", page_icon="🛡️", layout="wide"
)

# --- SIDEBAR: LIVE RBAC ROLE SWITCHER & SYSTEM STATUS ---
with st.sidebar:
  st.header("Database Security (RBAC)")
  db_role = st.radio(
      "Active MySQL Session User:",
      [
          "root (Admin - Full Access)",
          "analyst_user (L1_Analyst - Restricted)",
      ],
  )
  active_user = "root" if db_role.startswith("root") else "analyst_user"
  active_pass = (
      "root"  # <-- REPLACE WITH YOUR ROOT PASSWORD
      if active_user == "root"
      else "StrongPass@2026!"
  )

  st.info(
      f"**Connected as:** `{active_user}`\n\n"
      + (
          "Full privileges: `SELECT`, `INSERT`, `UPDATE`, `EXECUTE`"
          if active_user == "root"
          else "Restricted RBAC role: `SELECT` & `INSERT` on `forensic_logs`"
          " only. `UPDATE` & `CALL` blocked by MySQL."
      )
  )
  st.divider()
  st.markdown("**Student Details:**\n- Manik Dewan\n- J250210085 | 2nd Year")


# --- DATABASE CONNECTION ---
def get_connection():
  return mysql.connector.connect(
      host="localhost",
      user=active_user,
      password=active_pass,
      database="cyber_forensics_db",
  )


def run_query(query, params=None):
  conn = get_connection()
  df = pd.read_sql(query, conn, params=params)
  conn.close()
  return df


# --- HEADER ---
st.title("Cyber Forensics & Incident Log Management System")
st.caption(
    "B.Tech DBMS Mini-Project | MySQL 8.0 + Python (Triggers, Stored"
    " Procedures, Indexing & RBAC)  \n**Manik Dewan | J250210085 | 2nd Year**"
)

# --- TOP KPI METRIC CARDS ---
stats_df = run_query("""
    SELECT 
        (SELECT COUNT(*) FROM incidents) AS total_incidents,
        (SELECT COUNT(*) FROM incidents WHERE status != 'Closed') AS active_incidents,
        (SELECT COUNT(*) FROM compromised_hosts) AS total_hosts,
        (SELECT COUNT(*) FROM forensic_logs) AS total_logs,
        (SELECT COUNT(*) FROM custody_audit) AS audit_entries
""")

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Incidents", int(stats_df["total_incidents"][0]))
m2.metric(
    "Active Cases",
    int(stats_df["active_incidents"][0]),
    delta="Requires Action",
    delta_color="inverse",
)
m3.metric("Compromised Hosts", int(stats_df["total_hosts"][0]))
m4.metric("Forensic Logs", int(stats_df["total_logs"][0]))
m5.metric(
    "Custody Audits", int(stats_df["audit_entries"][0]), delta="Auto-Triggered"
)

st.divider()

tab1, tab2, tab3, tab4 = st.tabs([
    "🔍 1. Attack Timeline & Visuals",
    "📥 2. Ingest Evidence (Trigger Demo)",
    "🔒 3. Immutability & Stored Procedure",
    "📊 4. Analytics & EXPLAIN Index",
])

# ==========================================
# TAB 1: CHRONOLOGICAL TIMELINE + VISUAL CHART
# ==========================================
with tab1:
  incidents_df = run_query(
      "SELECT incident_id, title, severity, status FROM incidents"
  )

  col_sel, col_badge = st.columns([3, 1])
  with col_sel:
    selected_inc = st.selectbox(
        "Select Incident Case to Reconstruct",
        options=incidents_df["incident_id"].tolist(),
        format_func=lambda x: (
            f"#{x} -"
            f" {incidents_df.loc[incidents_df['incident_id']==x, 'title'].values[0]}"
        ),
    )

  inc_row = incidents_df[incidents_df["incident_id"] == selected_inc].iloc[0]
  with col_badge:
    st.markdown(f"**Severity:** `{inc_row['severity']}`")
    st.markdown(f"**Status:** `{inc_row['status']}`")

  timeline_query = """
        SELECT fl.log_id AS `Log ID`, fl.event_timestamp AS `Timestamp`,
               ch.hostname AS `Host`, ch.ip_address AS `Host IP`,
               fl.event_type AS `Event Type`, fl.source_ip AS `Attacker IP`,
               fl.raw_payload AS `Evidence Payload`, LEFT(fl.sha256_hash, 16) AS `SHA-256`
        FROM forensic_logs fl
        JOIN compromised_hosts ch ON fl.host_id = ch.host_id
        WHERE ch.incident_id = %s
        ORDER BY fl.event_timestamp ASC
    """
  timeline_df = run_query(timeline_query, params=(selected_inc,))

  if not timeline_df.empty:
    c_chart1, c_chart2 = st.columns(2)
    with c_chart1:
      st.markdown("**Events by Attack Type**")
      st.bar_chart(
          timeline_df["Event Type"].value_counts(),
          color="#ff4b4b",
          height=220,
      )
    with c_chart2:
      st.markdown("**Events per Compromised Host**")
      st.bar_chart(
          timeline_df["Host"].value_counts(), color="#1f77b4", height=220
      )

    st.markdown("**Reconstructed Chronological Attack Timeline (3-Table JOIN)**")
    st.dataframe(timeline_df, use_container_width=True, hide_index=True)
  else:
    st.warning("No forensic logs recorded for this incident yet.")

# ==========================================
# TAB 2: INGEST LOGS + LIVE TRIGGER DEMO
# ==========================================
with tab2:
  col1, col2 = st.columns([1, 1])

  with col1:
    st.subheader("Ingest New Forensic Log")
    hosts_df = run_query(
        "SELECT host_id, hostname, incident_id FROM compromised_hosts"
    )
    host_id = st.selectbox(
        "Target Compromised Host",
        options=hosts_df["host_id"].tolist(),
        format_func=lambda x: (
            f"Host #{x}:"
            f" {hosts_df.loc[hosts_df['host_id']==x, 'hostname'].values[0]}"
            f" (Incident #{hosts_df.loc[hosts_df['host_id']==x, 'incident_id'].values[0]})"
        ),
    )
    event_type = st.selectbox(
        "Event Type",
        [
            "FAILED_SSH_LOGIN",
            "MALWARE_DROP",
            "PRIVILEGE_ESCALATION",
            "OUTBOUND_C2_BEACON",
        ],
    )
    source_ip = st.text_input("Source IP Address", value="192.168.1.105")
    raw_payload = st.text_area(
        "Raw Log Payload",
        value="Unauthorized sudo execution attempt by user www-data",
    )

    if st.button("Insert Log into MySQL", type="primary"):
      conn = get_connection()
      cursor = conn.cursor()
      try:
        sha_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        sql = """
                    INSERT INTO forensic_logs (host_id, event_timestamp, event_type, source_ip, raw_payload, sha256_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
        cursor.execute(
            sql, (host_id, now, event_type, source_ip, raw_payload, sha_hash)
        )
        conn.commit()
        st.rerun()  # Immediately refreshes KPI cards & audit table
      except mysql.connector.Error as e:
        st.error(f"MySQL Error: {e.msg}")
      finally:
        cursor.close()
        conn.close()

  with col2:
    st.subheader("Live Chain-of-Custody Audit (`custody_audit`)")
    st.caption(
        "Populated automatically by `trg_after_log_insert` (`AFTER INSERT`)"
        " inside MySQL."
    )
    audit_df = run_query(
        "SELECT * FROM custody_audit ORDER BY audit_id DESC LIMIT 10"
    )
    st.dataframe(audit_df, use_container_width=True, hide_index=True)

# ==========================================
# TAB 3: TRIGGER TAMPER TEST & STORED PROCEDURE
# ==========================================
with tab3:
  c1, c2 = st.columns(2)

  with c1:
    st.subheader("1. Immutability Trigger (`BEFORE UPDATE`)")
    st.write("Attempt to modify an existing log payload to test tamper defense:")
    tamper_log_id = st.number_input("Log ID to Modify", min_value=1, value=1)
    fake_payload = st.text_input(
        "Altered Payload Text", value="Normal authorized login"
    )

    if st.button("Attempt Unauthorized Update", type="secondary"):
      conn = get_connection()
      cursor = conn.cursor()
      try:
        cursor.execute(
            "UPDATE forensic_logs SET raw_payload = %s WHERE log_id = %s",
            (fake_payload, tamper_log_id),
        )
        conn.commit()
        st.warning("Updated.")
      except mysql.connector.Error as err:
        st.error(f"Blocked by MySQL: {err.msg}")
      finally:
        cursor.close()
        conn.close()

  with c2:
    st.subheader("2. Stored Procedure (`sp_close_incident`)")
    st.write(
        "Closes an incident inside an ACID transaction only if logs exist:"
    )
    proc_inc_id = st.number_input("Incident ID to Close", min_value=1, value=1)

    if st.button("Execute sp_close_incident", type="primary"):
      conn = get_connection()
      cursor = conn.cursor()
      try:
        args = cursor.callproc("sp_close_incident", [proc_inc_id, ""])
        conn.commit()
        st.success(f"Procedure Result: **{args[1]}**")
      except mysql.connector.Error as err:
        st.error(f"Blocked by MySQL: {err.msg}")
      finally:
        cursor.close()
        conn.close()

# ==========================================
# TAB 4: REPORT QUERIES & INDEX OPTIMIZATION
# ==========================================
with tab4:
  c_left, c_right = st.columns([1.2, 1])

  with c_left:
    st.subheader("Investigator Workload (`LEFT JOIN` + `GROUP BY`)")
    workload_df = run_query("""
            SELECT inv.full_name AS Investigator, inv.clearance_level AS Clearance,
                   COUNT(i.incident_id) AS Total_Cases,
                   SUM(CASE WHEN i.severity = 'Critical' THEN 1 ELSE 0 END) AS Critical_Cases
            FROM investigators inv
            LEFT JOIN incidents i ON inv.investigator_id = i.lead_investigator_id
            GROUP BY inv.investigator_id, inv.full_name, inv.clearance_level
        """)
    st.dataframe(workload_df, use_container_width=True, hide_index=True)

  with c_right:
    st.subheader("Cases per Investigator")
    st.bar_chart(
        workload_df.set_index("Investigator")["Total_Cases"],
        color="#2ca02c",
        height=210,
    )

  st.divider()
  st.subheader("Query Performance Proof (`EXPLAIN` B-Tree Composite Index)")
  explain_df = run_query("""
        EXPLAIN SELECT * FROM forensic_logs 
        WHERE host_id = 1 AND event_timestamp BETWEEN '2026-11-01 00:00:00' AND '2026-11-30 23:59:59'
    """)
  st.dataframe(explain_df, use_container_width=True, hide_index=True)