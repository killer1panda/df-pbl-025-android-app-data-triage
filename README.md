# DF-PBL-025: Android App Data Triage
## Digital Forensics Project-Based Learning Assignment
**Candidate**: ARYAN (SAP ID: 500121030)  
**Institution**: School of Computer Science, UPES, Dehradun  
**Faculty Evaluator**: Dr. Keshav Sinha | Assistant Professor - SS  
**Performance Format**: Controlled Mini-Lab  

---

## 🎯 Project Overview & Forensic Scope

This repository contains the complete forensic engineering solution for assignment **DF-PBL-025**, assigned to **ARYAN (500121030)**:

> **Forensic Task**: *"Identify useful app databases, permissions and timestamps in a controlled Android dataset."*  
> **Key Deliverables**: Triage table, selected queries, findings, reproducible test, evidence inventory, formal PDF report, and 5-8 minute defense guide.

---

## 📦 Deliverables Checklist (As Per Instructor Guidelines)

| # | Submission Item Required | Corresponding File in Repository | Status |
| :- | :--- | :--- | :-: |
| 1 | **Report on PDF** | [`DF-PBL-025_Aryan_Forensic_Report.pdf`](file:///Users/ajay/Downloads/aryan/DF-PBL-025_Aryan_Forensic_Report.pdf) | **COMPLETE (6 Pages, Publication-Grade)** |
| 2 | **Evidence Inventory & Integrity Log** | [`triage_outputs/evidence_inventory_and_integrity_log.csv`](file:///Users/ajay/Downloads/aryan/triage_outputs/evidence_inventory_and_integrity_log.csv) | **COMPLETE (13 Artifacts, SHA-256 / MD5)** |
| 3 | **Technical Artefact** | [`android_triage_engine.py`](file:///Users/ajay/Downloads/aryan/android_triage_engine.py) | **COMPLETE (Modular Python 3.14 Triage Tool)** |
| 4 | **Controlled Experiment Output** | [`test_controlled_experiment.py`](file:///Users/ajay/Downloads/aryan/test_controlled_experiment.py)<br>[`triage_outputs/mini_lab_test_report.json`](file:///Users/ajay/Downloads/aryan/triage_outputs/mini_lab_test_report.json) | **COMPLETE (23/23 Assertions Passed, 100% Accuracy)** |
| 5 | **Triage Table & Queries** | [`triage_outputs/triage_summary_table.md`](file:///Users/ajay/Downloads/aryan/triage_outputs/triage_summary_table.md)<br>[`triage_outputs/selected_queries_and_findings.md`](file:///Users/ajay/Downloads/aryan/triage_outputs/selected_queries_and_findings.md) | **COMPLETE (Multi-App Triage & SQL Findings)** |
| 6 | **Limitations & Alternative Explanations** | Section 6 of Report & Defense Guide | **COMPLETE (Strict Observation vs Interpretation vs Inference)** |
| 7 | **Source & Tool Citations + AI Disclosure** | Sections 8 & 9 of Report | **COMPLETE (NIST SP 800-86, ISO/IEC 27037, Disclosure)** |
| 8 | **5 to 8 Minute Defense / Demo Guide** | [`DEFENSE_SCRIPT_AND_VIVA_GUIDE.md`](file:///Users/ajay/Downloads/aryan/DEFENSE_SCRIPT_AND_VIVA_GUIDE.md) | **COMPLETE (Timed Script, 8 Slides, Viva Q&A)** |

---

## 🚀 Quick Start & Live Demonstration

To execute a complete, live rerun of the entire forensic pipeline:

```bash
# Navigate to the workspace
cd /Users/ajay/Downloads/aryan

# Run the complete automated pipeline
./run_mini_lab.sh
```

### What happens in 3 seconds:
1. `generate_synthetic_evidence.py` verifies the controlled dataset and locks hashes in `evidence_master.zip`.
2. `android_triage_engine.py` audits manifest permissions, discovers SQLite databases, normalizes timestamps, and builds the unified chronological timeline.
3. `test_controlled_experiment.py` executes 23 automated assertions against ground-truth inputs.
4. `generate_pdf_report.py` re-compiles the formal 6-page academic PDF report.

---

## 📁 Repository Directory Structure

```text
/Users/ajay/Downloads/aryan/
├── README.md                                  # Complete repository documentation & navigation
├── run_mini_lab.sh                            # One-click automated runner for viva defense
├── android_triage_engine.py                    # Forensic triage engine (Databases, Permissions, Timestamps)
├── test_controlled_experiment.py               # Reproducible test harness (23 assertions)
├── generate_synthetic_evidence.py              # Controlled synthetic dataset generator with ground truth
├── generate_pdf_report.py                      # Academic PDF compiler
├── report_printable.html                       # HTML template for printable report
├── DF-PBL-025_Aryan_Forensic_Report.pdf        # Formal 6-page submission PDF report
├── DF-PBL-025_Aryan_Forensic_Report.md         # Full Markdown submission report
├── DEFENSE_SCRIPT_AND_VIVA_GUIDE.md            # 5-8 minute timed speech, slide outline, viva Q&A
├── evidence/
│   ├── evidence_original/                      # Immutable master baseline archive (SHA-256 sealed)
│   │   ├── evidence_master.zip
│   │   └── master_archive_sha256.txt
│   ├── evidence_working_copy/                  # Verified working copy parsed during triage
│   │   ├── com.securechat.messenger/           # Chat app (chat_history.db, contacts.db, prefs)
│   │   ├── com.quickpay.wallet/                # Wallet app (transactions.db, prefs)
│   │   ├── com.citycommute.rides/              # GPS ride app (trips.db, prefs)
│   │   └── com.stealth.calc_vault/             # Suspicious vault (vault_index.db, prefs)
│   ├── evidence_original_hashes.json           # Cryptographic baseline hash inventory
│   └── ground_truth_manifest.json              # Ground truth inputs for controlled mini-lab
└── triage_outputs/
    ├── evidence_inventory_and_integrity_log.csv # Cryptographic chain-of-custody audit log
    ├── triage_summary_table.md                  # Master forensic triage table (Markdown)
    ├── triage_summary_table.csv                 # Master forensic triage table (CSV)
    ├── selected_queries_and_findings.md        # Targeted forensic SQL queries and result tables
    ├── forensic_timeline.csv                   # Chronological cross-app unified timeline
    └── mini_lab_test_report.json               # Automated validation report with 23 assertions
```

---

## 🔬 Scientific Methodology & Forensic Distinction

As required by **Dr. Keshav Sinha**, all findings strictly distinguish between:
- **Observation**: Objective facts verified from storage bits (e.g., transaction record exists with timestamp `1716381600`).
- **Interpretation**: Technical mechanism (e.g., integer represents `2024-05-22 12:40:00 UTC`, debited via QuickPay API).
- **Inference**: High-level deduction (e.g., suspect coordinated funds transfer with Vikram Malhotra).
- **Alternative Explanations & Limitations**: Non-repudiation limits, lack of physical user proof, clock skew, and potential malware UI overlays.

---
**Candidate**: ARYAN (500121030)  
**Evaluator**: Dr. Keshav Sinha | Assistant Professor - SS | UPES, Dehradun
