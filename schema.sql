DROP DATABASE IF EXISTS cyber_forensics_db;
CREATE DATABASE cyber_forensics_db;
USE cyber_forensics_db;

-- 1. TABLES (3NF Normalized)
CREATE TABLE investigators (
    investigator_id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    clearance_level ENUM('L1_Analyst', 'L2_Responder', 'Admin') DEFAULT 'L1_Analyst'
);

CREATE TABLE incidents (
    incident_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    status ENUM('Open', 'Investigating', 'Contained', 'Closed') DEFAULT 'Open',
    detected_at DATETIME NOT NULL,
    lead_investigator_id INT,
    CONSTRAINT fk_lead_inv FOREIGN KEY (lead_investigator_id) 
        REFERENCES investigators(investigator_id) ON DELETE SET NULL
);

CREATE TABLE compromised_hosts (
    host_id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    os_type VARCHAR(50),
    incident_id INT NOT NULL,
    CONSTRAINT fk_host_inc FOREIGN KEY (incident_id) 
        REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE TABLE forensic_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    host_id INT NOT NULL,
    event_timestamp DATETIME(3) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45),
    raw_payload TEXT NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    CONSTRAINT fk_log_host FOREIGN KEY (host_id) 
        REFERENCES compromised_hosts(host_id) ON DELETE CASCADE
);

CREATE TABLE custody_audit (
    audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_id BIGINT NOT NULL,
    action_type VARCHAR(30) NOT NULL,
    performed_by VARCHAR(100) NOT NULL,
    action_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. PERFORMANCE INDEXING
CREATE INDEX idx_logs_host_time ON forensic_logs(host_id, event_timestamp);
CREATE INDEX idx_logs_source_ip ON forensic_logs(source_ip);

-- 3. TRIGGERS (Automated Chain-of-Custody & Tamper Prevention)
DELIMITER //

CREATE TRIGGER trg_after_log_insert
AFTER INSERT ON forensic_logs
FOR EACH ROW
BEGIN
    INSERT INTO custody_audit (log_id, action_type, performed_by)
    VALUES (NEW.log_id, 'INGESTED', CURRENT_USER());
END //

CREATE TRIGGER trg_prevent_log_tamper
BEFORE UPDATE ON forensic_logs
FOR EACH ROW
BEGIN
    IF OLD.sha256_hash <> NEW.sha256_hash OR OLD.raw_payload <> NEW.raw_payload THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'SECURITY VIOLATION: Forensic log evidence is immutable.';
    END IF;
END //

-- 4. STORED PROCEDURE (Transactional Incident Closure)
CREATE PROCEDURE sp_close_incident(IN p_incident_id INT, OUT p_result VARCHAR(100))
BEGIN
    DECLARE v_log_count INT DEFAULT 0;
    
    START TRANSACTION;
    
    SELECT COUNT(fl.log_id) INTO v_log_count
    FROM forensic_logs fl
    JOIN compromised_hosts ch ON fl.host_id = ch.host_id
    WHERE ch.incident_id = p_incident_id;
    
    IF v_log_count = 0 THEN
        ROLLBACK;
        SET p_result = 'ERROR: Cannot close incident without forensic evidence logs.';
    ELSE
        UPDATE incidents 
        SET status = 'Closed' 
        WHERE incident_id = p_incident_id;
        COMMIT;
        SET p_result = CONCAT('SUCCESS: Incident #', p_incident_id, ' closed with ', v_log_count, ' verified logs.');
    END IF;
END //

DELIMITER ;

-- 5. SECURITY FEATURES (Role-Based Access Control)
CREATE ROLE IF NOT EXISTS 'forensic_analyst';
GRANT SELECT ON cyber_forensics_db.* TO 'forensic_analyst';
GRANT INSERT ON cyber_forensics_db.forensic_logs TO 'forensic_analyst';

CREATE USER IF NOT EXISTS 'analyst_user'@'localhost' IDENTIFIED BY 'StrongPass@2026!';
GRANT 'forensic_analyst' TO 'analyst_user'@'localhost';
SET DEFAULT ROLE 'forensic_analyst' TO 'analyst_user'@'localhost';