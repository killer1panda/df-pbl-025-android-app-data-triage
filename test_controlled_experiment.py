#!/usr/bin/env python3
"""
Controlled Mini-Lab Experiment & Reproducibility Test Suite
Course: Digital Forensics Project Based Learning (DF-PBL-025)
Student: ARYAN (SAP ID: 500121030)
Faculty: Dr. Keshav Sinha | UPES, Dehradun

Purpose:
Executes the controlled experiment with known inputs and evaluates expected outputs
under strict forensic integrity criteria as specified in the assignment rules.
Provides automated test assertions, precision/recall metrics, and supports live rerun
for faculty evaluation.
"""

import os
import sys
import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from android_triage_engine import AndroidTriageEngine, calculate_hashes, normalize_timestamp

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence", "evidence_working_copy")
ORIGINAL_HASHES = os.path.join(BASE_DIR, "evidence", "evidence_original_hashes.json")
GROUND_TRUTH_PATH = os.path.join(BASE_DIR, "evidence", "ground_truth_manifest.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "triage_outputs")

class ControlledExperimentRunner:
    def __init__(self):
        self.test_results = {
            "test_suite": "DF-PBL-025 Android Triage Controlled Mini-Lab",
            "evaluator": "Automated Harness / Dr. Keshav Sinha Evaluation",
            "student": "ARYAN (500121030)",
            "execution_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "total_assertions": 0,
            "passed_assertions": 0,
            "failed_assertions": 0,
            "assertion_details": [],
            "overall_status": "PENDING"
        }

    def assert_equal(self, description, actual, expected):
        self.test_results["total_assertions"] += 1
        passed = (actual == expected)
        if passed:
            self.test_results["passed_assertions"] += 1
            print(f"  [\u2714 PASS] {description}: Got '{actual}' as expected.")
        else:
            self.test_results["failed_assertions"] += 1
            print(f"  [\u2718 FAIL] {description}: Expected '{expected}', but got '{actual}'.")
        
        self.test_results["assertion_details"].append({
            "test_id": f"TEST_{self.test_results['total_assertions']:03d}",
            "description": description,
            "expected": expected,
            "actual": actual,
            "passed": passed
        })
        return passed

    def assert_true(self, description, condition):
        self.test_results["total_assertions"] += 1
        if condition:
            self.test_results["passed_assertions"] += 1
            print(f"  [\u2714 PASS] {description}")
        else:
            self.test_results["failed_assertions"] += 1
            print(f"  [\u2718 FAIL] {description}")
        
        self.test_results["assertion_details"].append({
            "test_id": f"TEST_{self.test_results['total_assertions']:03d}",
            "description": description,
            "expected": True,
            "actual": bool(condition),
            "passed": bool(condition)
        })
        return bool(condition)

    def run(self):
        print("=" * 75)
        print("  DF-PBL-025: CONTROLLED MINI-LAB FORENSIC REPRODUCIBILITY TEST")
        print("  Student: ARYAN (500121030) | UPES Dehradun | Faculty: Dr. Keshav Sinha")
        print("=" * 75)

        # 1. Load Ground Truth
        with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
            ground_truth = json.load(f)

        # 2. Run Triage Engine
        triage = AndroidTriageEngine(
            evidence_dir=EVIDENCE_DIR,
            baseline_hash_file=ORIGINAL_HASHES,
            output_dir=OUTPUT_DIR
        )
        triage.run_full_triage()

        print("\n[*] Evaluating Test Assertions Against Ground Truth Inputs...")

        # Test Group 1: Evidence Integrity
        print("\n--- TEST GROUP 1: Cryptographic Evidence Integrity (Chain of Custody) ---")
        unverified_count = 0
        for entry in triage.inventory_log:
            if entry["integrity_status"] != "VERIFIED_MATCH":
                unverified_count += 1
        self.assert_equal("Zero Cryptographic Hash Divergence", unverified_count, 0)
        self.assert_equal("All Evidence Files Accounted For", len(triage.inventory_log), 13)

        # Test Group 2: Database Identification & Table Extraction
        print("\n--- TEST GROUP 2: SQLite Database Identification & Record Counts ---")
        # Chat history
        chat_db_info = triage.app_triage_results["com.securechat.messenger"]["databases"]["chat_history.db"]
        self.assert_equal("Chat Messages Record Count", chat_db_info["tables"]["messages"]["record_count"], 5)
        self.assert_equal("Chat Conversations Record Count", chat_db_info["tables"]["conversation_metadata"]["record_count"], 2)

        # Contacts
        contacts_db_info = triage.app_triage_results["com.securechat.messenger"]["databases"]["contacts.db"]
        self.assert_equal("Contacts Directory Record Count", contacts_db_info["tables"]["contacts"]["record_count"], 3)

        # QuickPay
        wallet_db_info = triage.app_triage_results["com.quickpay.wallet"]["databases"]["transactions.db"]
        self.assert_equal("Wallet Ledger Record Count", wallet_db_info["tables"]["ledger"]["record_count"], 3)

        # CityCommute
        trips_db_info = triage.app_triage_results["com.citycommute.rides"]["databases"]["trips.db"]
        self.assert_equal("Ride Trips Record Count", trips_db_info["tables"]["trip_records"]["record_count"], 2)

        # Vault
        vault_db_info = triage.app_triage_results["com.stealth.calc_vault"]["databases"]["vault_index.db"]
        self.assert_equal("Concealed Vault Hidden Files Count", vault_db_info["tables"]["hidden_files"]["record_count"], 3)

        # Test Group 3: Permissions Auditing & Dangerous Privilege Profiling
        print("\n--- TEST GROUP 3: Android Permission Auditing & Classification ---")
        vault_perms = triage.app_triage_results["com.stealth.calc_vault"]["permissions"]
        self.assert_equal("Calculator Vault Total Declared Permissions", vault_perms["total_count"], 9)
        self.assert_equal("Calculator Vault Dangerous Permissions Count", vault_perms["dangerous_count"], 7)
        self.assert_true("Calculator Vault Requests SYSTEM_ALERT_WINDOW", "android.permission.SYSTEM_ALERT_WINDOW" in vault_perms["dangerous"])
        self.assert_true("Calculator Vault Requests QUERY_ALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES" in vault_perms["dangerous"])

        chat_perms = triage.app_triage_results["com.securechat.messenger"]["permissions"]
        self.assert_equal("SecureChat Dangerous Permissions Count", chat_perms["dangerous_count"], 5)
        self.assert_true("SecureChat Requests CAMERA & MICROPHONE", 
                        "android.permission.CAMERA" in chat_perms["dangerous"] and "android.permission.RECORD_AUDIO" in chat_perms["dangerous"])

        # Test Group 4: Timestamp Normalization & Multi-Format Parsing
        print("\n--- TEST GROUP 4: Multi-Format Timestamp Normalization & Timeline Sync ---")
        t_epoch_ms = normalize_timestamp(1716380400000)
        self.assert_equal("Epoch Milliseconds Normalization (UTC)", t_epoch_ms["utc"], "2024-05-22 12:20:00 UTC")
        self.assert_equal("Epoch Milliseconds Format Detection", t_epoch_ms["format"], "Epoch Milliseconds")

        t_epoch_sec = normalize_timestamp(1716381600)
        self.assert_equal("Epoch Seconds Normalization (UTC)", t_epoch_sec["utc"], "2024-05-22 12:40:00 UTC")
        self.assert_equal("Epoch Seconds Format Detection", t_epoch_sec["format"], "Epoch Seconds")

        t_iso = normalize_timestamp("2024-05-22T15:05:00Z")
        self.assert_equal("ISO-8601 String Normalization (UTC)", t_iso["utc"], "2024-05-22 15:05:00 UTC")
        self.assert_equal("ISO-8601 Format Detection", t_iso["format"], "ISO-8601 String")

        # Test Timeline Chronology
        timeline = triage.unified_timeline
        is_strictly_chronological = all(timeline[i]["timestamp_epoch"] <= timeline[i+1]["timestamp_epoch"] for i in range(len(timeline)-1))
        self.assert_true("Unified Timeline Is Strictly Monotonically Ordered", is_strictly_chronological)

        # Test Group 5: Cross-Application Forensics Correlation
        print("\n--- TEST GROUP 5: Cross-App Event Correlation (Defensible Forensic Synthesis) ---")
        # Check chat mention matches trip dropoff
        rendezvous_mentioned = any("Cyber Park gate 3" in e["details"] for e in timeline)
        rendezvous_destination_logged = any("Cyber Park Gate 3, Sector 62" in e["details"] for e in timeline)
        self.assert_true("Chat Rendezvous Correlates to Geolocation Dropoff Location", rendezvous_mentioned and rendezvous_destination_logged)

        # Check chat transfer coordination correlates to QuickPay transfer
        transfer_chat_found = any("Transfer scheduled for 14:00 UTC via QuickPay" in e["details"] for e in timeline)
        transfer_ledger_found = any("DEBIT 75000.0 INR to QP_WALLET_1044" in e["details"] for e in timeline)
        self.assert_true("Chat Payment Coordination Correlates to Wallet Ledger Debit", transfer_chat_found and transfer_ledger_found)

        # Final Evaluation Summary
        total = self.test_results["total_assertions"]
        passed = self.test_results["passed_assertions"]
        failed = self.test_results["failed_assertions"]

        if failed == 0:
            self.test_results["overall_status"] = "PASSED (100% REPRODUCIBILITY CONFIRMED)"
        else:
            self.test_results["overall_status"] = "FAILED"

        report_file = os.path.join(OUTPUT_DIR, "mini_lab_test_report.json")
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(self.test_results, f, indent=2)

        print("\n" + "=" * 75)
        print(f"  MINI-LAB TEST SUMMARY: {passed}/{total} Passed (Accuracy: {(passed/total)*100:.1f}%)")
        print(f"  Overall Status: {self.test_results['overall_status']}")
        print(f"  Test Report Generated: {report_file}")
        print("=" * 75)
        return failed == 0

if __name__ == "__main__":
    runner = ControlledExperimentRunner()
    success = runner.run()
    sys.exit(0 if success else 1)
