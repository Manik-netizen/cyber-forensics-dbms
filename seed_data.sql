USE cyber_forensics_db;

INSERT INTO investigators (full_name, email, clearance_level) VALUES
('Manik Dewan', 'manik.dewan@admin.sample', 'Admin'),
('Aarav Sharma', 'aarav.sharma@soc.local', 'L2_Responder'),
('Priya Verma', 'priya.verma@soc.local', 'L1_Analyst');

INSERT INTO incidents (title, severity, status, detected_at, lead_investigator_id) VALUES
('SSH Brute Force & Lateral Movement', 'Critical', 'Investigating', '2026-11-12 02:14:00', 1),
('Unauthorized API Token Exfiltration', 'High', 'Open', '2026-11-13 18:45:00', 2);

INSERT INTO compromised_hosts (hostname, ip_address, os_type, incident_id) VALUES
('PROD-WEB-01', '10.0.12.15', 'Ubuntu 24.04 LTS', 1),
('DB-CORE-02', '10.0.12.22', 'Windows Server 2022', 1),
('API-GATEWAY-01', '10.0.14.9', 'Debian 12', 2);

-- Inserting logs automatically fires trg_after_log_insert to populate custody_audit
INSERT INTO forensic_logs (host_id, event_timestamp, event_type, source_ip, raw_payload, sha256_hash) VALUES
(1, '2026-11-12 02:14:11.120', 'FAILED_SSH_LOGIN', '185.220.101.4', 'Failed password for root from 185.220.101.4 port 51234', SHA2('Failed password for root from 185.220.101.4 port 51234', 256)),
(1, '2026-11-12 02:15:03.450', 'ACCEPTED_PUBLICKEY', '185.220.101.4', 'Accepted publickey for deploy from 185.220.101.4', SHA2('Accepted publickey for deploy from 185.220.101.4', 256)),
(2, '2026-11-12 02:19:40.800', 'PRIVILEGE_ESCALATION', '10.0.12.15', 'Suspicious PowerShell encoded command executed by NT AUTHORITY\\SYSTEM', SHA2('Suspicious PowerShell encoded command executed by NT AUTHORITY\\SYSTEM', 256));