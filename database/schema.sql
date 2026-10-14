PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    full_name VARCHAR(160) NOT NULL,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    department VARCHAR(120) NOT NULL,
    role VARCHAR(40) NOT NULL CHECK (role IN ('Security Administrator', 'Security Analyst', 'Regular Employee', 'Auditor', 'Service')),
    account_status VARCHAR(20) NOT NULL DEFAULT 'Active' CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    asset_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    operating_system VARCHAR(120),
    owner_id INTEGER NOT NULL REFERENCES users(id),
    department VARCHAR(120) NOT NULL,
    location VARCHAR(160) NOT NULL,
    criticality VARCHAR(20) NOT NULL CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    status VARCHAR(30) NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive', 'Under Maintenance'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id INTEGER NOT NULL REFERENCES users(id),
    asset_id INTEGER REFERENCES assets(id),
    assigned_analyst_id INTEGER REFERENCES users(id),
    status VARCHAR(30) NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    analyst_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY,
    threat_type VARCHAR(30) NOT NULL CHECK (threat_type IN ('IP Address', 'Domain', 'File Hash', 'Malware Signature', 'Other')),
    threat_value VARCHAR(512) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    source VARCHAR(160) NOT NULL,
    date_added DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_threat_type_value UNIQUE (threat_type, threat_value)
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(80) NOT NULL,
    description TEXT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service VARCHAR(80) NOT NULL
);

CREATE TRIGGER IF NOT EXISTS logs_immutable_update
BEFORE UPDATE ON logs
BEGIN
    SELECT RAISE(ABORT, 'logs are immutable');
END;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    cve_id VARCHAR(32),
    cvss_score FLOAT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    discovery_source VARCHAR(160) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    notification_type VARCHAR(40) NOT NULL CHECK (notification_type IN ('Incident Assignment', 'Security Alert', 'System Notification', 'Threat Alert', 'Vulnerability Alert')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status VARCHAR(10) NOT NULL DEFAULT 'Unread' CHECK (status IN ('Unread', 'Read')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME
);

CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    description TEXT NOT NULL,
    incident_category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY,
    playbook_id INTEGER NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    step_number INTEGER NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id INTEGER REFERENCES users(id),
    completed_at DATETIME,
    CONSTRAINT uq_response_actions_playbook_step UNIQUE (playbook_id, step_number)
);
