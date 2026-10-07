# 5 TO 8 MINUTE DEFENSE SCRIPT & VIVA VOCE GUIDE
## Digital Forensics Project-Based Learning (DF-PBL-025)
**Candidate**: ARYAN | **SAP ID**: 500121030 | **Institution**: UPES, Dehradun  
**Faculty Evaluator**: Dr. Keshav Sinha | Assistant Professor - SS  
**Project Title**: Android App Data Triage (Controlled Mini-Lab)

---

## PART 1: 5 TO 8 MINUTE TIMED DEFENSE SCRIPT

> **Instructions for Aryan**:  
> Speak in a clear, measured pace (approx. 120–140 words per minute). Keep your terminal open with the command `./run_mini_lab.sh` ready to run.

---

### [00:00 – 01:00] Slide 1: Introduction & Problem Statement
**Spoken Script**:
> *"Good morning, respected Dr. Keshav Sinha sir. My name is Aryan, SAP ID 500121030. Today, I am defending my Digital Forensics Project-Based Learning assignment, under Project Code DF-PBL-025, titled **Android App Data Triage**.*
>
> *In mobile investigations, application directories under `/data/data/` present a massive volume challenge. An investigator cannot perform exhaustive deep forensics on hundreds of apps during initial response. My assigned forensic question asks: **How do we identify useful app databases, permissions, and timestamps in a controlled Android dataset?**
>
> *To address this defensibly, I selected the **Mini-Lab** performance format, executing a controlled experiment with mathematically known inputs, expected outputs, and zero room for guesswork."*

---

### [01:00 – 02:15] Slide 2: Evidence Handling & Chain of Custody Integrity
**Spoken Script**:
> *"Before touching any data, I strictly enforced Assignment Rule Number 3: preserving originals and working solely on verified copies.
>
> *The raw extraction comprising 13 files across four distinct application packages was cryptographically hashed and sealed into an immutable master zip archive: `evidence_master.zip`. Its SHA-256 hash begins with `c4e14729...`.
>
> *All triage procedures were executed exclusively against our verified working copy. My engine generates an automated evidence inventory and integrity log—`evidence_inventory_and_integrity_log.csv`—which re-hashes each file on every run, confirming zero bit-level tampering and maintaining full ISO/IEC 27037 chain-of-custody compliance."*

---

### [02:15 – 03:45] Slide 3: Technical Execution & The Master Triage Table
**Spoken Script**:
> *"My technical artefact, `AndroidTriageEngine.py`, executes a 4-phase triage pipeline across four diverse apps:
>
> *1. **First, com.securechat.messenger**: The engine identified two SQLite databases—`chat_history.db` and `contacts.db`. It extracted five messages and three contacts. The timestamp format here is Unix Epoch Milliseconds. The query revealed communications planning a funds transfer and requesting an emergency physical meetup at Cyber Park Gate 3.
>
> *2. **Second, com.quickpay.wallet**: The engine located `transactions.db`. Here, timestamps are encoded in Unix Epoch Seconds. Triage revealed a debit transaction of 75,000 rupees to Vikram Malhotra, directly aligning with the chat conversation.
>
> *3. **Third, com.citycommute.rides**: The engine parsed `trips.db` where timestamps are ISO-8601 UTC strings. Crucially, trip records corroborate the suspect's physical travel to Cyber Park Gate 3 between 15:05 and 15:25 UTC.
>
> *4. **Fourth, com.stealth.calc_vault**: A disguised calculator app. Static manifest analysis flagged 7 dangerous permissions, including `SYSTEM_ALERT_WINDOW` and `QUERY_ALL_PACKAGES`—highly anomalous for a basic calculator. Database inspection of `vault_index.db` uncovered three hidden documents—including bank KYC and password databases encrypted with AES-256 in an obscure directory."*

---

### [03:45 – 04:45] Slide 4: Multi-Temporal Normalization & Unified Master Timeline
**Spoken Script**:
> *"A critical contribution of this project is solving temporal heterogeneity. Real-world Android apps store timestamps in different formats: epoch milliseconds, epoch seconds, and ISO strings.
>
> *My engine normalizes all disparate temporal schemes into Coordinated Universal Time (UTC) and Indian Standard Time (IST).
>
> *When plotted on a single timeline, the events snap into an evidential chain: at 12:00, sensitive files were concealed in the vault; at 12:20, messages coordinated the transfer; at 12:40, the 75,000 rupee debit executed; and at 15:05, the suspect traveled to the rendezvous site. No temporal distortion exists."*

---

### [04:45 – 05:45] Slide 5: Controlled Mini-Lab Execution & Live Rerun Demonstration
**Spoken Script**:
> *(Aryan turns to terminal or screen)*
> *"Sir, as required by the Mini-Lab rubric, I engineered an automated reproducibility test suite: `test_controlled_experiment.py`. It benchmarks our extraction against a known ground-truth manifest.
>
> *Allow me to demonstrate the live execution right now.*
> *(Aryan runs `./run_mini_lab.sh` or `python3 test_controlled_experiment.py`)*
>
> *As you can observe on screen, the test suite executes 23 automated forensic assertions spanning cryptographic integrity, database counts, permission detection, and cross-application correlation. All 23 assertions pass with 100% accuracy. If the evaluation committee requests modifying any input record, our engine dynamically re-verifies in seconds."*

---

### [05:45 – 06:45] Slide 6: Forensic Discipline: Observation vs. Interpretation vs. Inference
**Spoken Script**:
> *"In strict accordance with Dr. Keshav Sinha sir's assignment rules, my conclusion rigorously distinguishes between three levels of forensic truth:
>
> *1. **Observation**: What the bits objectively show. For example, row `TXN_20240522_001` exists with value 75,000.0 and timestamp integer `1716381600`.
>
> *2. **Interpretation**: The technical mechanism. The integer converts to 2024-05-22 12:40 UTC, representing an executed debit transaction in QuickPay.
>
> *3. **Inference**: High-level investigative deduction. We deduce that the user transferred funds to Vikram Malhotra.
>
> *However, as a forensic scientist, I note critical limitations: mobile artifacts alone **cannot prove physical attribution**. We cannot definitively claim who was holding the phone without biometric or physical surveillance corroboration. Furthermore, the overlay permission in the vault app introduces the technical possibility of UI spoofing. This restraint ensures my report is legally defensible in court."*

---

### [06:45 – 07:30] Slide 7: Conclusion, Citations & AI Disclosure
**Spoken Script**:
> *"In conclusion, this project satisfies all checklist items:
> - A formal 6-page academic PDF report.
> - An automated cryptographic evidence log.
> - A modular technical triage tool with reproducible test outputs.
> - Explicit citations of NIST SP 800-86 and ISO/IEC 27037 standards.
> - And a transparent AI assistance disclosure statement with independent local verification.
>
> *Thank you, sir. I am now open to your questions and ready for viva voce."*

---

## PART 2: SLIDE DECK VISUAL OUTLINE (8 SLIDES)

If you are presenting slides or sharing your screen, use these 8 structured slides:

| Slide # | Slide Title | Key Visuals & Bullet Points |
| :--- | :--- | :--- |
| **Slide 1** | **Title & Administrative Record** | • Project Code: `DF-PBL-025`<br>• Candidate: ARYAN (SAP ID: 500121030)<br>• Faculty: Dr. Keshav Sinha | UPES Dehradun<br>• Mode: Controlled Mini-Lab |
| **Slide 2** | **Forensic Question & Objectives** | • Core Question: Identify useful app databases, permissions, and timestamps.<br>• NIST SP 800-86 Triage Architecture.<br>• Controlled Ground-Truth Methodology. |
| **Slide 3** | **Evidence Handling & Integrity Log** | • Master Zip SHA-256: `c4e14729...`<br>• Verified Working Copy operations.<br>• Table showing 13 files with `VERIFIED MATCH` status. |
| **Slide 4** | **Master Forensic Triage Table** | • Summary table comparing the 4 apps (`com.securechat`, `com.quickpay`, `com.citycommute`, `com.stealth.calc_vault`).<br>• Databases, record counts, and dangerous permissions. |
| **Slide 5** | **Selected SQL Queries & Findings** | • Query snippets for chat messages, financial ledger, GPS trip coordinates, and hidden vault files.<br>• Corroboration of the rendezvous at Cyber Park Gate 3. |
| **Slide 6** | **Temporal Normalization Engine** | • Diagram showing Epoch ms, Epoch sec, and ISO-8601 mapping into unified UTC/IST.<br>• Chronological master event timeline. |
| **Slide 7** | **Controlled Mini-Lab Test Suite** | • Live screenshot / terminal run of `test_controlled_experiment.py`.<br>• 23 / 23 Assertions Passed (100% Accuracy). |
| **Slide 8** | **Limitations, Conclusion & Citations** | • Distinction Table: Observation vs Interpretation vs Inference.<br>• Attribution limitations & alternative explanations.<br>• AI Disclosure & NIST Citations. |

---

## PART 3: ANTICIPATED VIVA QUESTIONS & MODEL ANSWERS

Be completely prepared for these questions that Dr. Keshav Sinha or the faculty panel may ask:

### Q1: Why did you choose the "Mini-Lab" performance format?
> **Answer**:  
> *"Sir, the allocation sheet offered four formats: mini-lab, investigation memo, interactive prototype, or peer-audit. I chose the Mini-Lab because digital forensics requires scientific reproducibility. In a mini-lab, we define controlled inputs with known ground truth and prove our tool achieves 100% precision and recall. It allows the evaluator to test live reruns and verify assertions deterministically."*

### Q2: How does your triage engine detect whether an integer timestamp is in seconds or milliseconds?
> **Answer**:  
> *"Sir, in Unix time, current timestamps in seconds are around 1.7 billion (10 digits, e.g., 1716381600). Timestamps in milliseconds are 13 digits (greater than $10^{11}$, e.g., 1716380400000). My function `normalize_timestamp()` programmatically checks the magnitude: if the value exceeds $10^{11}$, it divides by 1000.0 before parsing. It also handles ISO-8601 text strings via `datetime.fromisoformat()`."*

### Q3: You found chat messages planning an illegal transfer. Can you claim in court that the phone's owner is guilty?
> **Answer**:  
> *"No, sir! That would violate the forensic rule distinguishing Observation from Inference. As an investigator, my **observation** is that the database stores a chat record originating from the local user account. My **technical interpretation** is that the messaging app generated and sent this payload. However, asserting that the defendant personally typed the message is an **inference** that requires independent corroboration—such as surveillance camera footage, fingerprint/biometric unlocks, or eyewitness testimony—because physical attribution and non-repudiation cannot be established from file system bits alone."*

### Q4: Why is `com.stealth.calc_vault` considered an anti-forensic risk?
> **Answer**:  
> *"Sir, two reasons: first, it masquerades as a benign calculator while housing an encrypted file vault (`vault_index.db`) holding sensitive PDFs and password databases. Second, its `AndroidManifest.xml` requests `SYSTEM_ALERT_WINDOW` (drawing overlays) and `QUERY_ALL_PACKAGES`. A standard calculator has zero functional need to inspect all installed packages or draw overlays over other apps. This indicates high privilege anomaly and potential for overlay spoofing."*

### Q5: What happens if I change the input dataset right now? Show me a live rerun.
> **Answer**:  
> *(Aryan executes `./run_mini_lab.sh`)*  
> *"Sir, if we modify any record in `generate_synthetic_evidence.py` or directly in the working database, running `./run_mini_lab.sh` immediately re-indexes the databases, updates the triage table, evaluates all 23 assertions, and compiles a fresh PDF report in less than 5 seconds."*

### Q6: How did you comply with the assignment's AI Assistance disclosure policy?
> **Answer**:  
> *"Sir, Rule #6 states: 'If AI assistance is used, disclose the tool and independently verify all outputs.' I included an explicit disclosure in Section 9 of the PDF report and in the technical code comments disclosing the use of Antigravity AI Assistant. Furthermore, I independently verified every cryptographic hash via Python's standard `hashlib`, executed the SQL queries in `sqlite3`, and validated all 23 assertions on my local machine."*

---

## PART 4: CHEAT SHEET COMMANDS

During the defense, keep these commands at your fingertips:

1. **One-Click Live Rerun**:
   ```bash
   ./run_mini_lab.sh
   ```

2. **Run Only the Test Suite**:
   ```bash
   python3 test_controlled_experiment.py
   ```

3. **Inspect the Triage Table**:
   ```bash
   cat triage_outputs/triage_summary_table.md
   ```

4. **Inspect the Chronological Timeline**:
   ```bash
   cat triage_outputs/forensic_timeline.csv
   ```

5. **Open the Generated PDF Report**:
   ```bash
   open DF-PBL-025_Aryan_Forensic_Report.pdf
   ```
