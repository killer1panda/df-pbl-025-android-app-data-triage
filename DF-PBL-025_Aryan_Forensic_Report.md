# DIGITAL FORENSICS PROJECT BASED LEARNING (DF-PBL)
## TECHNICAL INVESTIGATION REPORT & CONTROLLED MINI-LAB SPECIFICATION

---

### METADATA & ADMINISTRATIVE RECORD
- **Project Code**: DF-PBL-025
- **Student Name**: ARYAN
- **Student SAP ID**: 500121030
- **Course**: Digital Forensics Project Based Learning
- **Institution**: School of Computer Science, UPES, Dehradun
- **Faculty / Evaluator**: Dr. Keshav Sinha | Assistant Professor - SS | UPES, Dehradun
- **Assigned Topic**: Android App Data Triage
- **Forensic Question**: Identify useful app databases, permissions, and timestamps in a controlled Android dataset.
- **Performance Format**: Mini-lab (Controlled experiment with known inputs and expected outputs)
- **Investigation Date**: October 2026
- **Tool Suite**: AndroidTriageEngine v1.2.0-DF-PBL-025, Python 3.14 Standard Forensic Framework

---

## 1. PROBLEM STATEMENT & FORENSIC OBJECTIVES

### 1.1 Context
In modern digital investigations, mobile devices running the Android operating system harbor voluminous application partitions located under `/data/data/<package_name>/`. Conducting an exhaustive, manual forensic acquisition and reverse engineering pass across hundreds of installed applications is often prohibitively slow, creating critical evidentiary bottlenecks. Forensic triage—the rapid, forensically sound identification, preservation, extraction, and preliminary analysis of high-priority evidentiary artifacts—is therefore essential.

### 1.2 Specific Forensic Question (DF-PBL-025)
> *"How can an investigator systematically identify high-value SQLite databases, audit declared versus dangerous manifest permissions, normalize divergent application timestamp formats, and construct an evidentiary cross-application chronological timeline within a controlled Android dataset?"*

### 1.3 Key Technical Objectives
1. **Evidence Preservation**: Validate and maintain cryptographic hash baselines (SHA-256 and MD5) to satisfy ISO/IEC 27037 integrity standards.
2. **Permission Profiling**: Parse `AndroidManifest.xml` files to identify privilege escalation risks, invasive permissions, and security posture.
3. **Database Introspection**: Automatically discover SQLite databases (`.db`), enumerate table schemas, detect Write-Ahead Logging (`-wal`) and rollback journals (`-journal`), and execute targeted forensic queries.
4. **Temporal Normalization**: Resolve heterogeneous timestamp schemas (Unix Epoch in seconds, Unix Epoch in milliseconds, and ISO-8601 UTC strings) into a synchronized Coordinated Universal Time (UTC) and Indian Standard Time (IST, UTC+05:30) chronological master timeline.
5. **Controlled Mini-Lab Verification**: Subject the methodology to an automated reproducibility test asserting 100% precision and recall against known ground-truth inputs.

---

## 2. EVIDENCE INVENTORY & CRYPTOGRAPHIC INTEGRITY LOG

### 2.1 Master Archive Preservation
In accordance with Rule #3 (*"Preserve originals. Work on verified copies, calculate hashes where applicable and record tool names, versions, commands and timestamps"*), the original acquisition dataset was cryptographically hashed and sealed into an immutable archive:

- **Master Evidence Archive**: `evidence/evidence_original/evidence_master.zip`
- **Master Archive SHA-256**: `c4e1472981f829afcbdf6c9d5d66bc21e7af0d69793302afc44bb7d30bf71bc6`
- **Acquisition Timestamp**: `2026-10-07T15:35:52Z`
- **Verification Rule**: All triage operations were conducted strictly on verified forensic working copies (`evidence/evidence_working_copy/`).

### 2.2 Complete Evidence Inventory Table

| # | Package / Relative Path | Artifact Type | Size (Bytes) | SHA-256 Checksum | Integrity Status |
| :- | :--- | :--- | :- | :--- | :- |
| 1 | `com.securechat.messenger/AndroidManifest.xml` | XML Manifest | 845 | `2f9f8fa2ee71...` | **VERIFIED MATCH** |
| 2 | `com.securechat.messenger/shared_prefs/user_session.xml` | XML Preferences | 298 | `4d1b82ae76c1...` | **VERIFIED MATCH** |
| 3 | `com.securechat.messenger/databases/chat_history.db` | SQLite 3 Database | 16,384 | `9b3a1cf542d8...` | **VERIFIED MATCH** |
| 4 | `com.securechat.messenger/databases/contacts.db` | SQLite 3 Database | 16,384 | `7f41d9c028e3...` | **VERIFIED MATCH** |
| 5 | `com.quickpay.wallet/AndroidManifest.xml` | XML Manifest | 720 | `e5bc7d0912fa...` | **VERIFIED MATCH** |
| 6 | `com.quickpay.wallet/shared_prefs/wallet_config.xml` | XML Preferences | 265 | `6a4f9108dcbb...` | **VERIFIED MATCH** |
| 7 | `com.quickpay.wallet/databases/transactions.db` | SQLite 3 Database | 16,384 | `88c9df1023ba...` | **VERIFIED MATCH** |
| 8 | `com.citycommute.rides/AndroidManifest.xml` | XML Manifest | 682 | `1a7c85d99432...` | **VERIFIED MATCH** |
| 9 | `com.citycommute.rides/shared_prefs/rider_settings.xml` | XML Preferences | 240 | `3e498c11aa23...` | **VERIFIED MATCH** |
| 10 | `com.citycommute.rides/databases/trips.db` | SQLite 3 Database | 16,384 | `d552cf3a7719...` | **VERIFIED MATCH** |
| 11 | `com.stealth.calc_vault/AndroidManifest.xml` | XML Manifest | 912 | `0b77e8a93c72...` | **VERIFIED MATCH** |
| 12 | `com.stealth.calc_vault/shared_prefs/vault_config.xml` | XML Preferences | 315 | `5d28aa0714ee...` | **VERIFIED MATCH** |
| 13 | `com.stealth.calc_vault/databases/vault_index.db` | SQLite 3 Database | 16,384 | `b1e23f88045a...` | **VERIFIED MATCH** |

*Full 64-character SHA-256 and MD5 hashes are cataloged in `triage_outputs/evidence_inventory_and_integrity_log.csv`.*

---

## 3. METHODOLOGY & TECHNICAL FRAMEWORK

The investigation was conducted under the forensic framework established by **NIST Special Publication 800-86** (*Guide to Integrating Forensic Techniques into Incident Response*) and **NIST SP 800-101 Rev. 1** (*Guidelines on Mobile Device Forensics*).

```
   +-----------------------------------------------------------------------+
   |                     FORENSIC TRIAGE PIPELINE                          |
   +-----------------------------------------------------------------------+
                                      |
         [ Phase 1: Cryptographic Verification & Evidence Logging ]
         - Calculate SHA-256 & MD5 against master baseline archive
         - Enforce strict read-only working copy operations
                                      |
         [ Phase 2: Static Privilege & Permission Auditing ]
         - Parse AndroidManifest.xml per application
         - Categorize Normal vs. Dangerous (AOSP classification)
         - Compute relative privilege risk score
                                      |
         [ Phase 3: Database Discovery & Schema Introspection ]
         - Discover all SQLite database containers (.db, .sqlite)
         - Query sqlite_master and table_info pragma
         - Inspect Write-Ahead Logs (WAL) and rollback journals
                                      |
         [ Phase 4: Temporal Normalization & Chronological Master Timeline ]
         - Detect Epoch Milliseconds, Epoch Seconds, ISO-8601
         - Standardize to Coordinated Universal Time (UTC) & IST
         - Synthesize multi-app cross-correlation event matrix
```

---

## 4. TECHNICAL EXECUTION & RESULTS

### 4.1 Master Forensic Triage Table

The table below synthesizes the structural and evidentiary triage results generated by `AndroidTriageEngine`:

| App Package Name | Category & Role | Identified Databases | Tables & Record Counts | Dangerous Permissions | Temporal Encoding | Key Evidentiary Findings |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`com.securechat.messenger`** | Encrypted Messaging & VOIP | `chat_history.db`<br>`contacts.db` | `messages` (5 rec)<br>`conversation_metadata` (2 rec)<br>`contacts` (3 rec) | **5 Dangerous**<br>• `READ_CONTACTS`<br>• `WRITE_CONTACTS`<br>• `CAMERA`<br>• `RECORD_AUDIO`<br>• `ACCESS_FINE_LOCATION` | Unix Epoch ms (`timestamp_ms`) | Pre-transfer coordination messages, references to encrypted offshore file (`/sdcard/Download/offshore_notes.enc`), scheduled rendezvous at Cyber Park Gate 3. |
| **`com.quickpay.wallet`** | Financial Payments & Banking | `transactions.db` | `ledger` (3 rec) | **4 Dangerous**<br>• `USE_BIOMETRIC`<br>• `USE_FINGERPRINT`<br>• `READ_PHONE_STATE` | Unix Epoch sec (`timestamp_sec`) | High-value outbound transfer of ₹75,000.00 to Vikram M (`QP_WALLET_1044`), ride commute fee of ₹420.50, initial bank top-up ₹100,000.00. |
| **`com.citycommute.rides`** | Geo-Navigation & Ride-Hail | `trips.db` | `trip_records` (2 rec) | **4 Dangerous**<br>• `ACCESS_FINE_LOCATION`<br>• `ACCESS_COARSE_LOCATION`<br>• `ACCESS_BACKGROUND_LOCATION`<br>• `CALL_PHONE` | ISO-8601 UTC String (`start_time_iso`) | Geolocation tracking records verifying suspect travel from Sector 62 to rendezvous site (Cyber Park Gate 3) between 15:05 UTC and 15:25 UTC; Vehicle: `UP16-AB-4321`. |
| **`com.stealth.calc_vault`** | Anti-Forensic Disguised Vault | `vault_index.db` | `hidden_files` (3 rec) | **7 Dangerous**<br>• `READ_EXTERNAL_STORAGE`<br>• `WRITE_EXTERNAL_STORAGE`<br>• `MANAGE_EXTERNAL_STORAGE`<br>• `SYSTEM_ALERT_WINDOW`<br>• `QUERY_ALL_PACKAGES`<br>• `READ_CALL_LOG`<br>• `ACCESS_FINE_LOCATION` | Unix Epoch ms (`added_epoch_ms`) | Concealed directory `/sdcard/.calculator_hidden` housing encrypted documents (`swiss_bank_kyc.pdf`, `passwords_backup.kdbx`, `client_ledger_confidential.xlsx`) with AES-256-CBC/GCM. |

---

### 4.2 Selected Forensic Queries and Evidential Outputs

#### Query 1: Communications Flow & Evidentiary Attachment Extraction
- **Target**: `com.securechat.messenger/databases/chat_history.db`
- **Objective**: Reconstruct the communication chain between the suspect and conspirators.
- **Forensic SQL Query**:
```sql
SELECT 
    msg_id, 
    sender, 
    recipient, 
    message_body, 
    timestamp_ms, 
    status, 
    attachment_path 
FROM messages 
ORDER BY timestamp_ms ASC;
```

**Query Results Table**:
| msg_id | Sender | Recipient | Message Content | Normalized Timestamp (UTC) | Status | Attachment |
| :-: | :--- | :--- | :--- | :--- | :-: | :--- |
| 1 | `self` | `+91-9123456780` | Hey Vikram, did you review the Q3 financial statement? | 2024-05-22 12:20:00 UTC | READ | _None_ |
| 2 | `+91-9123456780` | `self` | Yes Aryan, look at the encrypted offshore transfer notes. | 2024-05-22 12:22:00 UTC | READ | `/sdcard/Download/offshore_notes.enc` |
| 3 | `self` | `+91-9123456780` | Got it. Transfer scheduled for 14:00 UTC via QuickPay. | 2024-05-22 12:23:20 UTC | READ | _None_ |
| 4 | `+91-9988776655` | `self` | Emergency meet at Cyber Park gate 3 at 15:30. | 2024-05-22 12:30:00 UTC | DELIVERED | _None_ |
| 5 | `self` | `+91-9988776655` | On my way. Booking cab now. | 2024-05-22 12:31:00 UTC | SENT | _None_ |

---

#### Query 2: Financial Ledger Audit & Disputed Fund Transfer
- **Target**: `com.quickpay.wallet/databases/transactions.db`
- **Objective**: Identify monetary transfers matching the communications timetable.
- **Forensic SQL Query**:
```sql
SELECT 
    txn_id, 
    account_source, 
    counterparty, 
    amount, 
    currency, 
    txn_type, 
    timestamp_sec, 
    remarks, 
    status 
FROM ledger 
ORDER BY timestamp_sec ASC;
```

**Query Results Table**:
| Transaction ID | Account Source | Counterparty | Amount | Type | Normalized Timestamp (UTC) | Remarks | Status |
| :--- | :--- | :--- | :--- | :-: | :--- | :--- | :-: |
| `TXN_20240521_098` | `QP_BANK_ICICI` | `QP_WALLET_8831` | ₹100,000.00 | CREDIT | 2024-05-21 12:40:00 UTC | Top-up from primary account | SUCCESS |
| `TXN_20240522_001` | `QP_WALLET_8831` | `QP_WALLET_1044 (Vikram M)` | ₹75,000.00 | DEBIT | 2024-05-22 12:40:00 UTC | Project Consulting Milestone 1 | SUCCESS |
| `TXN_20240522_002` | `QP_WALLET_8831` | `MERCHANT_902 (CityCommute)`| ₹420.50 | DEBIT | 2024-05-22 12:48:20 UTC | Trip payment commute | SUCCESS |

---

#### Query 3: Geolocation Coordinates & Physical Rendezvous Corroboration
- **Target**: `com.citycommute.rides/databases/trips.db`
- **Objective**: Validate whether the device holder traveled to the physical meeting point.
- **Forensic SQL Query**:
```sql
SELECT 
    trip_id, 
    driver_name, 
    pickup_address, 
    pickup_lat, 
    pickup_lng, 
    dropoff_address, 
    dropoff_lat, 
    dropoff_lng, 
    start_time_iso, 
    end_time_iso, 
    fare_amount, 
    vehicle_plate 
FROM trip_records 
ORDER BY start_time_iso ASC;
```

**Query Results Table**:
| Trip ID | Driver Name | Origin Coordinates | Destination Coordinates | Start Time (UTC) | Dropoff Time (UTC) | Fare | Vehicle Plate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `TRIP_88112` | Mohd. Shakeel | Connaught Place (28.6315, 77.2167) | DLF CyberCity (28.4950, 77.0895) | 2024-05-21 09:15:00 UTC | 2024-05-21 10:02:00 UTC | ₹680.00 | DL1Z-CD-8899 |
| `TRIP_88190` | Ramesh Kumar | Sector 62 Noida (28.6280, 77.3649) | Cyber Park Gate 3 (28.6310, 77.3712) | 2024-05-22 15:05:00 UTC | 2024-05-22 15:25:00 UTC | ₹420.50 | UP16-AB-4321 |

---

#### Query 4: Anti-Forensic Concealment Catalog Inspection
- **Target**: `com.stealth.calc_vault/databases/vault_index.db`
- **Objective**: Expose disguised files hidden under calculator facade.
- **Forensic SQL Query**:
```sql
SELECT 
    item_id, 
    original_filename, 
    obfuscated_path, 
    file_type, 
    file_size_bytes, 
    added_epoch_ms, 
    encryption_cipher, 
    status 
FROM hidden_files 
ORDER BY added_epoch_ms ASC;
```

**Query Results Table**:
| ID | Original Filename | Obfuscated Path | File Type | Size | Added Timestamp (UTC) | Cipher | Status |
| :-: | :--- | :--- | :--- | :-: | :--- | :--- | :-: |
| 1 | `swiss_bank_kyc.pdf` | `/sdcard/.calculator_hidden/f7a90b1.bin` | DOCUMENT | 345 KB | 2024-05-22 12:00:00 UTC | AES-256-CBC | LOCKED |
| 2 | `passwords_backup.kdbx` | `/sdcard/.calculator_hidden/d8c11e4.bin` | KEYSTORE | 81 KB | 2024-05-22 12:05:00 UTC | AES-256-GCM | LOCKED |
| 3 | `client_ledger_confidential.xlsx`| `/sdcard/.calculator_hidden/a1b2c3d.bin` | SPREADSHEET | 512 KB | 2024-05-22 12:15:00 UTC | AES-256-CBC | LOCKED |

---

### 4.3 Unified Chronological Multi-App Master Timeline

By normalizing epoch milliseconds, epoch seconds, and ISO-8601 strings into a single temporal axis, the investigative engine synthesizes the cross-application event chain:

```
[2024-05-22 12:00:00 UTC] com.stealth.calc_vault      -> Hidden vault stores swiss_bank_kyc.pdf (AES-256-CBC)
[2024-05-22 12:05:00 UTC] com.stealth.calc_vault      -> Hidden vault stores passwords_backup.kdbx
[2024-05-22 12:15:00 UTC] com.stealth.calc_vault      -> Hidden vault stores client_ledger_confidential.xlsx
[2024-05-22 12:20:00 UTC] com.securechat.messenger    -> Suspect sends chat to Vikram M regarding Q3 statement
[2024-05-22 12:22:00 UTC] com.securechat.messenger    -> Vikram M sends offshore notes attachment reference
[2024-05-22 12:23:20 UTC] com.securechat.messenger    -> Suspect agrees: "Transfer scheduled for 14:00 UTC via QuickPay"
[2024-05-22 12:30:00 UTC] com.securechat.messenger    -> Conspirator calls for emergency meet at Cyber Park gate 3
[2024-05-22 12:31:00 UTC] com.securechat.messenger    -> Suspect confirms: "On my way. Booking cab now"
[2024-05-22 12:40:00 UTC] com.quickpay.wallet         -> Outbound transfer of ₹75,000.00 executed to Vikram M
[2024-05-22 12:48:20 UTC] com.quickpay.wallet         -> Payment of ₹420.50 executed to CityCommute Merchant
[2024-05-22 15:05:00 UTC] com.citycommute.rides       -> Suspect picked up by driver Ramesh Kumar (UP16-AB-4321)
[2024-05-22 15:25:00 UTC] com.citycommute.rides       -> Suspect arrives at Cyber Park Gate 3 (Rendezvous Location)
```

---

## 5. REPRODUCIBLE TEST: THE CONTROLLED MINI-LAB EXPERIMENT

### 5.1 Test Specification & Protocol
In direct fulfillment of the **Mini-lab** performance format (*"Run a controlled experiment with known inputs and expected outputs"*), an automated test harness (`test_controlled_experiment.py`) was engineered.

- **Known Inputs**: Defined in `evidence/ground_truth_manifest.json` (exact package names, permission counts, database schemas, records, hashes).
- **Execution**: The triage engine processes the raw dataset and extracts all findings.
- **Expected Outputs Evaluation**: The test suite evaluates 23 forensic assertions across 5 core categories.

### 5.2 Automated Assertion Matrix

```
===========================================================================
  DF-PBL-025: CONTROLLED MINI-LAB FORENSIC REPRODUCIBILITY TEST
  Student: ARYAN (500121030) | UPES Dehradun | Faculty: Dr. Keshav Sinha
===========================================================================

TEST GROUP 1: Cryptographic Evidence Integrity
  [✔ PASS] Zero Cryptographic Hash Divergence (0 unverified files)
  [✔ PASS] All Evidence Files Accounted For (13/13 verified)

TEST GROUP 2: SQLite Database Identification & Record Counts
  [✔ PASS] Chat Messages Record Count (Expected: 5, Actual: 5)
  [✔ PASS] Chat Conversations Record Count (Expected: 2, Actual: 2)
  [✔ PASS] Contacts Directory Record Count (Expected: 3, Actual: 3)
  [✔ PASS] Wallet Ledger Record Count (Expected: 3, Actual: 3)
  [✔ PASS] Ride Trips Record Count (Expected: 2, Actual: 2)
  [✔ PASS] Concealed Vault Hidden Files Count (Expected: 3, Actual: 3)

TEST GROUP 3: Android Permission Auditing & Classification
  [✔ PASS] Calculator Vault Total Declared Permissions (Expected: 9, Actual: 9)
  [✔ PASS] Calculator Vault Dangerous Permissions Count (Expected: 7, Actual: 7)
  [✔ PASS] Calculator Vault Requests SYSTEM_ALERT_WINDOW (True)
  [✔ PASS] Calculator Vault Requests QUERY_ALL_PACKAGES (True)
  [✔ PASS] SecureChat Dangerous Permissions Count (Expected: 5, Actual: 5)
  [✔ PASS] SecureChat Requests CAMERA & MICROPHONE (True)

TEST GROUP 4: Multi-Format Timestamp Normalization & Timeline Sync
  [✔ PASS] Epoch Milliseconds Normalization -> 2024-05-22 12:20:00 UTC
  [✔ PASS] Epoch Milliseconds Format Detection -> 'Epoch Milliseconds'
  [✔ PASS] Epoch Seconds Normalization -> 2024-05-22 12:40:00 UTC
  [✔ PASS] Epoch Seconds Format Detection -> 'Epoch Seconds'
  [✔ PASS] ISO-8601 String Normalization -> 2024-05-22 15:05:00 UTC
  [✔ PASS] ISO-8601 Format Detection -> 'ISO-8601 String'
  [✔ PASS] Unified Timeline Is Strictly Monotonically Ordered (True)

TEST GROUP 5: Cross-App Event Correlation (Forensic Synthesis)
  [✔ PASS] Chat Rendezvous Correlates to Geolocation Dropoff Location (True)
  [✔ PASS] Chat Payment Coordination Correlates to Wallet Ledger Debit (True)

===========================================================================
  MINI-LAB SUMMARY: 23/23 PASSED (100% REPRODUCIBILITY CONFIRMED)
===========================================================================
```

### 5.3 Faculty Live Rerun Instructions
If the instructor (Dr. Keshav Sinha) requests a live rerun or modified input data during the defense:
1. Open a terminal in the project directory:
   ```bash
   cd /Users/ajay/Downloads/aryan
   ```
2. Execute the one-click verification script:
   ```bash
   ./run_mini_lab.sh
   ```
3. To test with new or modified data: Edit `generate_synthetic_evidence.py` or modify records in `evidence/evidence_working_copy/` and re-run.

---

## 6. LIMITATIONS AND ALTERNATIVE EXPLANATIONS

In strict adherence to Dr. Keshav Sinha's core assignment rule:
> *"A conclusion must distinguish observation, interpretation and inference. Do not claim authorship, intent or guilt from one artifact alone."*

The findings are partitioned systematically across the three forensic tiers:

### 6.1 Distinction Framework: Observation vs. Interpretation vs. Inference

| Tier | Definition | Examples from Case DF-PBL-025 |
| :--- | :--- | :--- |
| **Observation**<br>*(Objective Physical/Digital Fact)* | Raw, unmanipulated data bytes existing in the persistent storage media at the time of examination. | • File `transactions.db` contains record `TXN_20240522_001` with value `75000.0`, status `SUCCESS`, and integer `1716381600`.<br>• `chat_history.db` contains string *"Transfer scheduled for 14:00 UTC via QuickPay"* associated with timestamp `1716380600000`.<br>• Manifest declares `android.permission.SYSTEM_ALERT_WINDOW`. |
| **Interpretation**<br>*(Technical Mechanism)* | Explaining how the operating system or application software generated the observed data artifact. | • The integer `1716381600` represents Unix Epoch Seconds, translating technically to `2024-05-22 12:40:00 UTC`.<br>• The QuickPay application processed a debit transaction requesting ₹75,000.00 from the local account to counterparty `QP_WALLET_1044`.<br>• The calculator app has permission to draw overlays on other active applications. |
| **Inference**<br>*(Investigative Deduction)* | Contextual deductions linking technical interpretations to human intent, knowledge, or conspiracy. | • The device user intentionally coordinated an illicit offshore milestone transfer with Vikram Malhotra.<br>• The calculator vault application was intentionally installed to conceal financial records from law enforcement. |

### 6.2 Forensic Limitations & Alternative Explanations
1. **Absence of Proof of Identity (Non-Repudiation)**:
   - *Alternative Explanation*: While records indicate messages originated from `"self"` and payments originated from the device wallet, an artifact alone **cannot prove who was holding the physical device**. The device could have been operated by an authorized third party, stolen, or compromised by remote administrative software (RAT).
2. **Clock Skew and User Tampering**:
   - *Alternative Explanation*: Device clocks can be manually modified by users or may suffer from uncalibrated Network Time Protocol (NTP) drift. Although database timestamps align chronologically, network server logs (cellular tower records or backend server access logs) must be subpoenaed to corroborate local device timestamps.
3. **Malware Overlays & False Intent**:
   - *Alternative Explanation*: The presence of `android.permission.SYSTEM_ALERT_WINDOW` in `com.stealth.calc_vault` could indicate overlay attack capabilities. A malicious application could potentially inject simulated UI clicks or hijack payment screens without the user's conscious knowledge.
4. **Lack of Volatile Memory (RAM)**:
   - *Limitation*: Ephemeral artifacts—such as uncommitted chat sessions, active session encryption keys, or memory-only background sync processes—are absent from a static file system triage.

---

## 7. DEFENSIBLE CONCLUSION

Based strictly on the reproducible triage of the controlled Android dataset (DF-PBL-025):
1. **Useful Databases Identified**: Four distinct primary SQLite databases (`chat_history.db`, `transactions.db`, `trips.db`, `vault_index.db`) were successfully isolated, introspected, and parsed, yielding 13 high-value forensic records.
2. **Permissions Audited**: The triage engine flagged high-risk permissions, notably identifying that `com.stealth.calc_vault` declared 7 dangerous permissions—including overlay and full package inspection capabilities inconsistent with a standard calculator utility.
3. **Timestamps Normalized**: Three disparate temporal encodings (epoch milliseconds, epoch seconds, and ISO-8601 strings) were successfully translated into synchronized UTC and IST timelines without temporal distortion.
4. **Defensible Evidentiary Assessment**: The synchronized timeline demonstrates high technical correlation between communications planning, financial fund movements, physical ride dispatch, and file concealment. However, definitive claims of criminal intent or physical identity cannot be made from these local mobile artifacts alone and require corroboration through cloud provider logs, bank statements, and cell tower telemetry.

---

## 8. SOURCE AND TOOL CITATIONS

### 8.1 Standards & Regulatory Frameworks
1. **NIST SP 800-86**: Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to Integrating Forensic Techniques into Incident Response*. National Institute of Standards and Technology.
2. **NIST SP 800-101 Rev. 1**: Ayers, R., Brothers, S., & Jansen, W. (2014). *Guidelines on Mobile Device Forensics*. NIST Special Publication 800-101 Revision 1.
3. **ISO/IEC 27037:2012**: *Information technology — Security techniques — Guidelines for identification, collection, acquisition and preservation of digital evidence*.

### 8.2 Technical Documentation & Specifications
4. **Android Open Source Project (AOSP)**: *Android Permissions Architecture and Protection Levels*. Google Developers Documentation (API Level 34).
5. **SQLite Development Team**: *SQLite Database File Format Documentation & Write-Ahead Logging Specification*. https://www.sqlite.org/fileformat2.html.

### 8.3 Tools Employed
- **Python 3.14 Forensic Runtime**: Used for cryptographic hashing (`hashlib`), database access (`sqlite3`), and XML DOM parsing (`xml.etree.ElementTree`).
- **AndroidTriageEngine v1.2.0-DF-PBL-025**: Custom forensic triage utility authored for this assignment.
- **Controlled Mini-Lab Test Suite (`test_controlled_experiment.py`)**: Reproducibility validation harness.

---

## 9. DISCLOSURE OF AI ASSISTANCE & INDEPENDENT VERIFICATION

In compliance with the assignment rules (*"If AI assistance is used, disclose the tool and independently verify all outputs"*):

- **Tool Utilized**: Antigravity AI Assistant (Google DeepMind).
- **Scope of Assistance**: Assistance was utilized for structuring the forensic framework, formatting the markdown tables, optimizing Python SQLite query scripts, and writing the test harness scaffold.
- **Independent Verification**:
  1. All cryptographic hashes were independently calculated and validated via standard Python `hashlib` implementations.
  2. All SQL queries were executed against real SQLite databases and verified directly using `sqlite3` CLI inspections.
  3. All 23 assertions in the test suite were executed locally and confirmed to pass with 100% precision.
  4. All conclusions and legal-forensic disclaimers were independently authored and vetted to ensure strict adherence to forensic science standards.

---
**Report Submitted By**: ARYAN (SAP ID: 500121030)  
**Evaluator**: Dr. Keshav Sinha | Assistant Professor - SS | UPES, Dehradun  
**Signature**: *Aryan (Digital Forensics Student, UPES)*  
**Date**: October 2026
