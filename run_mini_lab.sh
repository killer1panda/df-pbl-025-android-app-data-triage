#!/usr/bin/env bash
# ==============================================================================
# DF-PBL-025: Android App Data Triage - Mini-Lab Automated Runner
# Student: ARYAN (SAP ID: 500121030) | Faculty: Dr. Keshav Sinha | UPES Dehradun
# ==============================================================================

set -e

echo "=========================================================================="
echo "  DIGITAL FORENSICS PROJECT BASED LEARNING (DF-PBL-025)"
echo "  Investigator: ARYAN | SAP ID: 500121030 | Mode: Controlled Mini-Lab"
echo "=========================================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/4] Step 1: Verifying/Generating Master Controlled Evidence Dataset..."
python3 generate_synthetic_evidence.py

echo ""
echo "[2/4] Step 2: Executing Android App Forensic Triage Engine..."
python3 android_triage_engine.py

echo ""
echo "[3/4] Step 3: Running Controlled Experiment Reproducibility Test Suite..."
python3 test_controlled_experiment.py

echo ""
echo "[4/4] Step 4: Compiling Formal Forensic PDF Report..."
python3 generate_pdf_report.py

echo ""
echo "=========================================================================="
echo "  [SUCCESS] All Mini-Lab Execution Stages Completed Successfully!"
echo "  Artifacts Generated:"
echo "    - Forensic PDF Report: $SCRIPT_DIR/DF-PBL-025_Aryan_Forensic_Report.pdf"
echo "    - Triage Summary Table: $SCRIPT_DIR/triage_outputs/triage_summary_table.md"
echo "    - Selected Queries:    $SCRIPT_DIR/triage_outputs/selected_queries_and_findings.md"
echo "    - Evidence Log (CSV):  $SCRIPT_DIR/triage_outputs/evidence_inventory_and_integrity_log.csv"
echo "    - Event Timeline:      $SCRIPT_DIR/triage_outputs/forensic_timeline.csv"
echo "    - Mini-Lab Test JSON:  $SCRIPT_DIR/triage_outputs/mini_lab_test_report.json"
echo "=========================================================================="
