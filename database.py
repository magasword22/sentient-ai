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

