# Android App Forensic Data Triage Table
**Project**: DF-PBL-025 | **Investigator**: ARYAN (SAP ID: 500121030) | **Institution**: UPES, Dehradun
**Generated**: 2026-10-07 15:42:21 UTC | **Engine**: AndroidTriageEngine v1.2.0-DF-PBL-025

| App Package | App Role / Type | Databases Identified | Tables & Total Records | Dangerous Permissions Count | Timestamp Formats | Key Forensic Artifacts Found |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `com.citycommute.rides` | Ride Hailing & Geo-Navigation | trips.db | trip_records (2 rec) (Total: 2) | **4 dangerous**<br>(ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, ACCESS_BACKGROUND_LOCATION...) | ISO-8601 UTC Strings (`start_time_iso`) | 2 GPS trip records, pickup/dropoff coordinates, route destination matching rendezvous (Cyber Park Gate 3), driver details. |
| `com.quickpay.wallet` | Financial Wallet & Digital Payments | transactions.db | ledger (3 rec) (Total: 3) | **4 dangerous**<br>(USE_BIOMETRIC, USE_FINGERPRINT, READ_PHONE_STATE...) | Unix Epoch Seconds (`timestamp_sec`) | Financial ledger (3 transactions), high-value transfer of ₹75,000 to Vikram M, KYC profile in shared_prefs. |
| `com.securechat.messenger` | Encrypted Instant Messaging | chat_history.db<br>contacts.db | messages (5 rec)<br>conversation_metadata (2 rec)<br>contacts (3 rec) (Total: 10) | **5 dangerous**<br>(READ_CONTACTS, WRITE_CONTACTS, CAMERA...) | Unix Epoch Milliseconds (`timestamp_ms`) | 5 chat messages, contact directory (3 contacts), attachment paths (`offshore_notes.enc`), unread counts. |
| `com.stealth.calc_vault` | Anti-Forensic Calculator Vault | vault_index.db | hidden_files (3 rec) (Total: 3) | **7 dangerous**<br>(READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE...) | Unix Epoch Milliseconds (`added_epoch_ms`) | 3 encrypted/hidden files (`swiss_bank_kyc.pdf`, `passwords_backup.kdbx`), AES-256 ciphers, hidden directory path. |
