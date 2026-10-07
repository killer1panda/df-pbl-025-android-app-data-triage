#!/usr/bin/env python3
"""
Controlled Android Evidence Generator
Course: Digital Forensics Project Based Learning (DF-PBL-025)
Student: ARYAN (SAP ID: 500121030)
Faculty: Dr. Keshav Sinha | UPES, Dehradun

Purpose:
Generates a realistic, controlled Android app extraction dataset representing
/data/data/ application directories across four distinct apps with known ground truth.
Includes SQLite databases, AndroidManifest.xml permissions, shared_prefs XML files,
epoch timestamps (both seconds and milliseconds), and creates a master integrity baseline.
"""

import os
import sqlite3
import hashlib
import json
import shutil
import zipfile
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
ORIGINAL_DIR = os.path.join(EVIDENCE_DIR, "evidence_original")
WORKING_DIR = os.path.join(EVIDENCE_DIR, "evidence_working_copy")

def compute_hash(filepath, algo='sha256'):
    h = hashlib.sha256() if algo == 'sha256' else hashlib.md5()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def create_manifest_xml(target_path, package_name, permissions, version_name="2.4.1", version_code="241"):
    perm_xml_entries = "\n".join([f'    <uses-permission android:name="{p}" />' for p in permissions])
    xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}">

{perm_xml_entries}

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="{package_name.split('.')[-1]}"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(xml_content.strip())

def create_shared_prefs_xml(target_path, prefs_dict):
    entries = []
    for k, v in prefs_dict.items():
        if isinstance(v, bool):
            entries.append(f'    <boolean name="{k}" value="{str(v).lower()}" />')
        elif isinstance(v, int):
            entries.append(f'    <int name="{k}" value="{v}" />')
        elif isinstance(v, float):
            entries.append(f'    <float name="{k}" value="{v}" />')
        elif isinstance(v, str):
            entries.append(f'    <string name="{k}">{v}</string>')
    
    xml_content = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
{chr(10).join(entries)}
</map>
"""
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(xml_content.strip())

def build_securechat_app(app_dir):
    # 1. Manifest
    perms = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.VIBRATE",
        "android.permission.RECEIVE_BOOT_COMPLETED"
    ]
    create_manifest_xml(os.path.join(app_dir, "AndroidManifest.xml"), "com.securechat.messenger", perms)

    # 2. Shared Prefs
    prefs = {
        "user_phone": "+91-9876543210",
        "account_id": "usr_991823",
        "encryption_enabled": True,
        "backup_frequency": "daily",
        "last_sync_timestamp": 1716382000000, # 2024-05-22 12:46:40 UTC (ms)
        "biometric_unlock": True
    }
    create_shared_prefs_xml(os.path.join(app_dir, "shared_prefs", "user_session.xml"), prefs)

    # 3. Databases
    db_dir = os.path.join(app_dir, "databases")
    os.makedirs(db_dir, exist_ok=True)

    # 3a. chat_history.db
    chat_db_path = os.path.join(db_dir, "chat_history.db")
    conn = sqlite3.connect(chat_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE messages (
            msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            message_body TEXT,
            timestamp_ms INTEGER NOT NULL,
            status TEXT CHECK(status IN ('SENT', 'DELIVERED', 'READ')),
            attachment_path TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE conversation_metadata (
            conv_id TEXT PRIMARY KEY,
            contact_number TEXT,
            unread_count INTEGER,
            last_activity_ms INTEGER
        )
    """)

    # Ground truth messages with epoch millisecond timestamps
    messages_data = [
        ("self", "+91-9123456780", "Hey Vikram, did you review the Q3 financial statement?", 1716380400000, "READ", None),
        ("+91-9123456780", "self", "Yes Aryan, look at the encrypted offshore transfer notes.", 1716380520000, "READ", "/sdcard/Download/offshore_notes.enc"),
        ("self", "+91-9123456780", "Got it. Transfer scheduled for 14:00 UTC via QuickPay.", 1716380600000, "READ", None),
        ("+91-9988776655", "self", "Emergency meet at Cyber Park gate 3 at 15:30.", 1716381000000, "DELIVERED", None),
        ("self", "+91-9988776655", "On my way. Booking cab now.", 1716381060000, "SENT", None)
    ]
    cur.executemany("INSERT INTO messages (sender, recipient, message_body, timestamp_ms, status, attachment_path) VALUES (?, ?, ?, ?, ?, ?)", messages_data)

    metadata_data = [
        ("conv_001", "+91-9123456780", 0, 1716380600000),
        ("conv_002", "+91-9988776655", 0, 1716381060000)
    ]
    cur.executemany("INSERT INTO conversation_metadata VALUES (?, ?, ?, ?)", metadata_data)
    conn.commit()
    conn.close()

    # 3b. contacts.db
    contacts_db_path = os.path.join(db_dir, "contacts.db")
    conn = sqlite3.connect(contacts_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE contacts (
            contact_id INTEGER PRIMARY KEY,
            display_name TEXT,
            phone_number TEXT UNIQUE,
            email TEXT,
            starred INTEGER DEFAULT 0
        )
    """)
    contacts_data = [
        (1, "Vikram Malhotra", "+91-9123456780", "v.malhotra@zenithcorp.org", 1),
        (2, "Rohan Deshmukh", "+91-9988776655", "rohan.d@infraglobal.net", 0),
        (3, "Sneha Patel", "+91-9456781234", "spatel@securemail.com", 1)
    ]
    cur.executemany("INSERT INTO contacts VALUES (?, ?, ?, ?, ?)", contacts_data)
    conn.commit()
    conn.close()

def build_quickpay_app(app_dir):
    perms = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.READ_PHONE_STATE",
        "android.permission.POST_NOTIFICATIONS"
    ]
    create_manifest_xml(os.path.join(app_dir, "AndroidManifest.xml"), "com.quickpay.wallet", perms)

    prefs = {
        "wallet_id": "QP_WALLET_8831",
        "kyc_verified": True,
        "daily_limit_inr": 200000,
        "two_factor_auth": True,
        "last_login_epoch_sec": 1716381500
    }
    create_shared_prefs_xml(os.path.join(app_dir, "shared_prefs", "wallet_config.xml"), prefs)

    db_dir = os.path.join(app_dir, "databases")
    os.makedirs(db_dir, exist_ok=True)
    tx_db_path = os.path.join(db_dir, "transactions.db")
    conn = sqlite3.connect(tx_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE ledger (
            txn_id TEXT PRIMARY KEY,
            account_source TEXT,
            counterparty TEXT,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'INR',
            txn_type TEXT CHECK(txn_type IN ('DEBIT', 'CREDIT', 'ESCROW')),
            timestamp_sec INTEGER NOT NULL,
            remarks TEXT,
            status TEXT
        )
    """)
    # Unix epoch in SECONDS
    tx_data = [
        ("TXN_20240522_001", "QP_WALLET_8831", "QP_WALLET_1044 (Vikram M)", 75000.00, "INR", "DEBIT", 1716381600, "Project Consulting Milestone 1", "SUCCESS"),
        ("TXN_20240522_002", "QP_WALLET_8831", "MERCHANT_902 (CityCommute)", 420.50, "INR", "DEBIT", 1716382100, "Trip payment commute", "SUCCESS"),
        ("TXN_20240521_098", "QP_BANK_ICICI", "QP_WALLET_8831", 100000.00, "INR", "CREDIT", 1716295200, "Top-up from primary account", "SUCCESS")
    ]
    cur.executemany("INSERT INTO ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", tx_data)
    conn.commit()
    conn.close()

def build_citycommute_app(app_dir):
    perms = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.CALL_PHONE"
    ]
    create_manifest_xml(os.path.join(app_dir, "AndroidManifest.xml"), "com.citycommute.rides", perms)

    prefs = {
        "rider_rating": 4.88,
        "default_payment": "QUICKPAY",
        "auto_share_trip": False,
        "saved_home_lat": 28.6139,
        "saved_home_lng": 77.2090
    }
    create_shared_prefs_xml(os.path.join(app_dir, "shared_prefs", "rider_settings.xml"), prefs)

    db_dir = os.path.join(app_dir, "databases")
    os.makedirs(db_dir, exist_ok=True)
    trips_db_path = os.path.join(db_dir, "trips.db")
    conn = sqlite3.connect(trips_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE trip_records (
            trip_id TEXT PRIMARY KEY,
            driver_name TEXT,
            pickup_address TEXT,
            pickup_lat REAL,
            pickup_lng REAL,
            dropoff_address TEXT,
            dropoff_lat REAL,
            dropoff_lng REAL,
            start_time_iso TEXT,
            end_time_iso TEXT,
            fare_amount REAL,
            vehicle_plate TEXT
        )
    """)
    trips_data = [
        ("TRIP_88190", "Ramesh Kumar", "Block C, Sector 62, Noida", 28.6280, 77.3649, "Cyber Park Gate 3, Sector 62", 28.6310, 77.3712, "2024-05-22T15:05:00Z", "2024-05-22T15:25:00Z", 420.50, "UP16-AB-4321"),
        ("TRIP_88112", "Mohd. Shakeel", "Connaught Place Inner Circle", 28.6315, 77.2167, "DLF CyberCity Building 10", 28.4950, 77.0895, "2024-05-21T09:15:00Z", "2024-05-21T10:02:00Z", 680.00, "DL1Z-CD-8899")
    ]
    cur.executemany("INSERT INTO trip_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", trips_data)
    conn.commit()
    conn.close()

def build_stealth_calc_vault_app(app_dir):
    # Suspicious app with invasive permissions hiding encrypted records
    perms = [
        "android.permission.INTERNET",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.READ_CALL_LOG",
        "android.permission.ACCESS_FINE_LOCATION"
    ]
    create_manifest_xml(os.path.join(app_dir, "AndroidManifest.xml"), "com.stealth.calc_vault", perms, "1.0.3", "103")

    prefs = {
        "passcode_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "fake_calc_history": "12+45=57; 100/4=25",
        "intruder_selfie_enabled": True,
        "vault_active": True,
        "obscure_directory": "/sdcard/.calculator_hidden"
    }
    create_shared_prefs_xml(os.path.join(app_dir, "shared_prefs", "vault_config.xml"), prefs)

    db_dir = os.path.join(app_dir, "databases")
    os.makedirs(db_dir, exist_ok=True)
    vault_db_path = os.path.join(db_dir, "vault_index.db")
    conn = sqlite3.connect(vault_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE hidden_files (
            item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            obfuscated_path TEXT NOT NULL,
            file_type TEXT,
            file_size_bytes INTEGER,
            added_epoch_ms INTEGER,
            encryption_cipher TEXT,
            status TEXT
        )
    """)
    files_data = [
        ("swiss_bank_kyc.pdf", "/sdcard/.calculator_hidden/f7a90b1.bin", "DOCUMENT", 345120, 1716379200000, "AES-256-CBC", "LOCKED"),
        ("passwords_backup.kdbx", "/sdcard/.calculator_hidden/d8c11e4.bin", "KEYSTORE", 81920, 1716379500000, "AES-256-GCM", "LOCKED"),
        ("client_ledger_confidential.xlsx", "/sdcard/.calculator_hidden/a1b2c3d.bin", "SPREADSHEET", 512000, 1716380100000, "AES-256-CBC", "LOCKED")
    ]
    cur.executemany("INSERT INTO hidden_files (original_filename, obfuscated_path, file_type, file_size_bytes, added_epoch_ms, encryption_cipher, status) VALUES (?, ?, ?, ?, ?, ?, ?)", files_data)
    conn.commit()
    conn.close()

def main():
    print("[*] Generating controlled Android forensic dataset...")
    if os.path.exists(WORKING_DIR):
        shutil.rmtree(WORKING_DIR)
    os.makedirs(WORKING_DIR, exist_ok=True)
    os.makedirs(ORIGINAL_DIR, exist_ok=True)

    app_builders = {
        "com.securechat.messenger": build_securechat_app,
        "com.quickpay.wallet": build_quickpay_app,
        "com.citycommute.rides": build_citycommute_app,
        "com.stealth.calc_vault": build_stealth_calc_vault_app
    }

    for pkg_name, builder_fn in app_builders.items():
        pkg_path = os.path.join(WORKING_DIR, pkg_name)
        os.makedirs(pkg_path, exist_ok=True)
        builder_fn(pkg_path)
        print(f"  [+] Built controlled package: {pkg_name}")

    # Build ground truth manifest
    ground_truth = {
        "metadata": {
            "project_code": "DF-PBL-025",
            "student_name": "ARYAN",
            "student_id": "500121030",
            "generation_time_utc": datetime.now(timezone.utc).isoformat(),
            "target_os": "Android 14 (API 34)",
            "acquisition_type": "Controlled Logical/File System Extraction"
        },
        "packages": {
            "com.securechat.messenger": {
                "role": "Encrypted Instant Messaging",
                "manifest_permissions_count": 9,
                "dangerous_permissions": [
                    "android.permission.READ_CONTACTS",
                    "android.permission.WRITE_CONTACTS",
                    "android.permission.CAMERA",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION"
                ],
                "databases": ["chat_history.db", "contacts.db"],
                "expected_message_count": 5,
                "expected_contact_count": 3,
                "timestamp_format": "Unix Epoch Milliseconds"
            },
            "com.quickpay.wallet": {
                "role": "Financial Payment & Wallet",
                "manifest_permissions_count": 6,
                "dangerous_permissions": [
                    "android.permission.USE_BIOMETRIC",
                    "android.permission.USE_FINGERPRINT",
                    "android.permission.READ_PHONE_STATE"
                ],
                "databases": ["transactions.db"],
                "expected_transaction_count": 3,
                "total_debit_amount": 75420.50,
                "timestamp_format": "Unix Epoch Seconds"
            },
            "com.citycommute.rides": {
                "role": "Ride Hailing & Geo Navigation",
                "manifest_permissions_count": 5,
                "dangerous_permissions": [
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION",
                    "android.permission.ACCESS_BACKGROUND_LOCATION",
                    "android.permission.CALL_PHONE"
                ],
                "databases": ["trips.db"],
                "expected_trip_count": 2,
                "timestamp_format": "ISO-8601 UTC Strings"
            },
            "com.stealth.calc_vault": {
                "role": "Disguised Vault / Suspicious File Container",
                "manifest_permissions_count": 9,
                "dangerous_permissions": [
                    "android.permission.READ_EXTERNAL_STORAGE",
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                    "android.permission.MANAGE_EXTERNAL_STORAGE",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.QUERY_ALL_PACKAGES",
                    "android.permission.READ_CALL_LOG",
                    "android.permission.ACCESS_FINE_LOCATION"
                ],
                "databases": ["vault_index.db"],
                "expected_hidden_files_count": 3,
                "timestamp_format": "Unix Epoch Milliseconds"
            }
        }
    }

    manifest_path = os.path.join(EVIDENCE_DIR, "ground_truth_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"  [+] Ground truth manifest written to: {manifest_path}")

    # Compute hash inventory for all generated files
    inventory = []
    for root, _, files in os.walk(WORKING_DIR):
        for f in files:
            full_p = os.path.join(root, f)
            rel_p = os.path.relpath(full_p, WORKING_DIR)
            sha256 = compute_hash(full_p, 'sha256')
            md5 = compute_hash(full_p, 'md5')
            sz = os.path.getsize(full_p)
            inventory.append({
                "relative_path": rel_p,
                "size_bytes": sz,
                "sha256": sha256,
                "md5": md5
            })

    hash_manifest_path = os.path.join(EVIDENCE_DIR, "evidence_original_hashes.json")
    with open(hash_manifest_path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    print(f"  [+] Cryptographic hash baseline recorded ({len(inventory)} items).")

    # Create immutable master zip
    zip_target = os.path.join(ORIGINAL_DIR, "evidence_master.zip")
    with zipfile.ZipFile(zip_target, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(WORKING_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, WORKING_DIR)
                zf.write(full_path, rel_path)
    
    master_zip_sha256 = compute_hash(zip_target, 'sha256')
    print(f"  [+] Master evidence locked in zip: {zip_target}")
    print(f"  [+] Master Archive SHA-256: {master_zip_sha256}")

    with open(os.path.join(ORIGINAL_DIR, "master_archive_sha256.txt"), "w") as f:
        f.write(f"Archive: evidence_master.zip\nSHA-256: {master_zip_sha256}\nTimestamp: {datetime.now(timezone.utc).isoformat()}\n")

    print("[*] Controlled Android Dataset generation complete successfully!")

if __name__ == "__main__":
    main()
