# Selected Forensic Queries and Detailed Findings
**Project**: DF-PBL-025 (Android App Data Triage) | **Student**: ARYAN (500121030) | **UPES, Dehradun**

## Overview
This document enumerates the exact SQL queries executed against the triaged Android application databases, their forensic justifications, and the extracted evidential findings.

### com.securechat.messenger -> Database: `chat_history.db`
**Query Title**: Ordered Communications & Attachments
```sql
SELECT msg_id, sender, recipient, message_body, timestamp_ms, status, attachment_path FROM messages ORDER BY timestamp_ms ASC;
```
**Extracted Findings Table**:
| msg_id | sender | recipient | body | timestamp_utc | timestamp_ist | status | attachment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | self | +91-9123456780 | Hey Vikram, did you review the Q3 financial statement? | 2024-05-22 12:20:00 UTC | 2024-05-22 17:50:00 IST | READ | None |
| 2 | +91-9123456780 | self | Yes Aryan, look at the encrypted offshore transfer notes. | 2024-05-22 12:22:00 UTC | 2024-05-22 17:52:00 IST | READ | /sdcard/Download/offshore_notes.enc |
| 3 | self | +91-9123456780 | Got it. Transfer scheduled for 14:00 UTC via QuickPay. | 2024-05-22 12:23:20 UTC | 2024-05-22 17:53:20 IST | READ | None |
| 4 | +91-9988776655 | self | Emergency meet at Cyber Park gate 3 at 15:30. | 2024-05-22 12:30:00 UTC | 2024-05-22 18:00:00 IST | DELIVERED | None |
| 5 | self | +91-9988776655 | On my way. Booking cab now. | 2024-05-22 12:31:00 UTC | 2024-05-22 18:01:00 IST | SENT | None |

### com.securechat.messenger -> Database: `contacts.db`
**Query Title**: Associated Contact Identities
```sql
SELECT contact_id, display_name, phone_number, email, starred FROM contacts;
```
**Extracted Findings Table**:
| id | name | phone | email | starred |
| --- | --- | --- | --- | --- |
| 1 | Vikram Malhotra | +91-9123456780 | v.malhotra@zenithcorp.org | True |
| 2 | Rohan Deshmukh | +91-9988776655 | rohan.d@infraglobal.net | False |
| 3 | Sneha Patel | +91-9456781234 | spatel@securemail.com | True |

### com.quickpay.wallet -> Database: `transactions.db`
**Query Title**: Ledger Audit & High-Value Transfers
```sql
SELECT txn_id, account_source, counterparty, amount, currency, txn_type, timestamp_sec, remarks, status FROM ledger ORDER BY timestamp_sec ASC;
```
**Extracted Findings Table**:
| txn_id | source | counterparty | amount | type | timestamp_utc | timestamp_ist | remarks | status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TXN_20240521_098 | QP_BANK_ICICI | QP_WALLET_8831 | 100,000.00 INR | CREDIT | 2024-05-21 12:40:00 UTC | 2024-05-21 18:10:00 IST | Top-up from primary account | SUCCESS |
| TXN_20240522_001 | QP_WALLET_8831 | QP_WALLET_1044 (Vikram M) | 75,000.00 INR | DEBIT | 2024-05-22 12:40:00 UTC | 2024-05-22 18:10:00 IST | Project Consulting Milestone 1 | SUCCESS |
| TXN_20240522_002 | QP_WALLET_8831 | MERCHANT_902 (CityCommute) | 420.50 INR | DEBIT | 2024-05-22 12:48:20 UTC | 2024-05-22 18:18:20 IST | Trip payment commute | SUCCESS |

### com.citycommute.rides -> Database: `trips.db`
**Query Title**: Geolocational Trip Tracking & Vehicle Identifiers
```sql
SELECT trip_id, driver_name, pickup_address, dropoff_address, start_time_iso, end_time_iso, fare_amount, vehicle_plate FROM trip_records ORDER BY start_time_iso ASC;
```
**Extracted Findings Table**:
| trip_id | driver | pickup | dropoff | start_utc | end_utc | fare | plate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TRIP_88112 | Mohd. Shakeel | Connaught Place Inner Circle (28.6315, 77.2167) | DLF CyberCity Building 10 (28.495, 77.0895) | 2024-05-21 09:15:00 UTC | 2024-05-21 10:02:00 UTC | 680.0 | DL1Z-CD-8899 |
| TRIP_88190 | Ramesh Kumar | Block C, Sector 62, Noida (28.628, 77.3649) | Cyber Park Gate 3, Sector 62 (28.631, 77.3712) | 2024-05-22 15:05:00 UTC | 2024-05-22 15:25:00 UTC | 420.5 | UP16-AB-4321 |

### com.stealth.calc_vault -> Database: `vault_index.db`
**Query Title**: Obfuscated Vault Catalog & Ciphers
```sql
SELECT item_id, original_filename, obfuscated_path, file_type, file_size_bytes, added_epoch_ms, encryption_cipher, status FROM hidden_files ORDER BY added_epoch_ms ASC;
```
**Extracted Findings Table**:
| id | original_name | obfuscated_path | type | size | added_utc | cipher | status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | swiss_bank_kyc.pdf | /sdcard/.calculator_hidden/f7a90b1.bin | DOCUMENT | 345120 bytes | 2024-05-22 12:00:00 UTC | AES-256-CBC | LOCKED |
| 2 | passwords_backup.kdbx | /sdcard/.calculator_hidden/d8c11e4.bin | KEYSTORE | 81920 bytes | 2024-05-22 12:05:00 UTC | AES-256-GCM | LOCKED |
| 3 | client_ledger_confidential.xlsx | /sdcard/.calculator_hidden/a1b2c3d.bin | SPREADSHEET | 512000 bytes | 2024-05-22 12:15:00 UTC | AES-256-CBC | LOCKED |

