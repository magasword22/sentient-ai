import sqlite3
import os
from datetime import datetime

DB_FILE = "audits.db"

def init_db():
    """Initialise la base de données SQLite."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            target TEXT NOT NULL,
            hosts_found INTEGER NOT NULL,
            vulnerabilities_found INTEGER NOT NULL,
            report_path TEXT NOT NULL
        )
    ''')
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN vulnerabilities_json TEXT")
    except sqlite3.OperationalError:
        pass
        
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            frequency TEXT NOT NULL,
            nmap_mode TEXT NOT NULL,
            nuclei_tags TEXT,
            report_lang TEXT NOT NULL,
            last_run TEXT,
            next_run TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    # Insérer les utilisateurs par défaut s'ils n'existent pas
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        import hashlib
        admin_hash = hashlib.sha256("admin0022".encode()).hexdigest()
        client_hash = hashlib.sha256("client0022".encode()).hexdigest()
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ("admin", admin_hash, "admin"))
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', ("client", client_hash, "client"))
    conn.commit()
    conn.close()

def add_scan(target, hosts_found, vulnerabilities_found, report_path, vulnerabilities_json=None):
    """Ajoute une entrée dans l'historique."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO scans (date, target, hosts_found, vulnerabilities_found, report_path, vulnerabilities_json)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (now, target, hosts_found, vulnerabilities_found, report_path, vulnerabilities_json))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def get_history():
    """Récupère tout l'historique des scans."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT id, date, target, hosts_found, vulnerabilities_found, report_path, vulnerabilities_json FROM scans ORDER BY id DESC')
        rows = cursor.fetchall()
        has_json_col = True
    except sqlite3.OperationalError:
        cursor.execute('SELECT id, date, target, hosts_found, vulnerabilities_found, report_path FROM scans ORDER BY id DESC')
        rows = cursor.fetchall()
        has_json_col = False
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "date": row[1],
            "target": row[2],
            "hosts_found": row[3],
            "vulnerabilities_found": row[4],
            "report_path": row[5],
            "vulnerabilities_json": row[6] if has_json_col else None
        })
    return history

def add_schedule(target, frequency, nmap_mode, nuclei_tags, report_lang, next_run):
    """Ajoute une planification de scan."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO schedules (target, frequency, nmap_mode, nuclei_tags, report_lang, next_run)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (target, frequency, nmap_mode, nuclei_tags, report_lang, next_run))
    conn.commit()
    conn.close()

def get_schedules():
    """Récupère toutes les planifications."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, target, frequency, nmap_mode, nuclei_tags, report_lang, last_run, next_run FROM schedules')
    rows = cursor.fetchall()
    conn.close()
    
    schedules = []
    for row in rows:
        schedules.append({
            "id": row[0],
            "target": row[1],
            "frequency": row[2],
            "nmap_mode": row[3],
            "nuclei_tags": row[4],
            "report_lang": row[5],
            "last_run": row[6],
            "next_run": row[7]
        })
    return schedules

def delete_schedule(schedule_id):
    """Supprime une planification."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM schedules WHERE id = ?', (schedule_id,))
    conn.commit()
    conn.close()

def update_schedule_last_run(schedule_id, last_run, next_run):
    """Met à jour les dates d'exécution d'une planification."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?', (last_run, next_run, schedule_id))
    conn.commit()
    conn.close()

def verify_user(username, password):
    """Vérifie les informations d'un utilisateur local et retourne (is_valid, role)."""
    import hashlib
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('SELECT role FROM users WHERE username = ? AND password_hash = ?', (username, pwd_hash))
    row = cursor.fetchone()
    conn.close()
    if row:
        return True, row[0]
    return False, None

def add_user(username, password, role):
    """Ajoute un utilisateur dans la base de données."""
    import hashlib
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (username, pwd_hash, role))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

def delete_user(username):
    """Supprime un utilisateur local (sauf admin et client par défaut)."""
    if username in ["admin", "client"]:
        return False
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    return True

def get_users():
    """Récupère la liste des utilisateurs."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role FROM users')
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]


