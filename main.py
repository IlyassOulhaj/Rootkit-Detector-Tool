import sys
import time

# IMPORT YOUR TEAM'S MODULES
# This looks for process_check.py and file_check.py in the same folder
import process_check
import file_check

def run_full_scan():
    print("========================================")
    print("      LINUX ROOTKIT DETECTOR v1.0       ")
    print("========================================")
    
    detections = 0

    # --- STEP 1: Run Ilyass's Module ---
    print("\n[+] Launching Process Scan (Module: Ilyass)...")
    time.sleep(1) # Just for effect
    
    # We call your function. It runs, prints its own text, 
    # and returns True (if infected) or False (if clean).
    is_process_infected = process_check.scan_process()
    
    if is_process_infected:
        detections += 1

    # --- STEP 2: Run Ayoub's Module ---
    print("\n[+] Launching File Integrity Scan (Module: Ayoub)...")
    time.sleep(1)
    
    # We call Ayoub's function.
    is_file_infected = file_check.scan_files()
    
    if is_file_infected:
        detections += 1

    # --- STEP 3: Final Report ---
    print("\n========================================")
    print("             FINAL REPORT               ")
    print("========================================")
    
    if detections == 0:
        print("✅ SYSTEM STATUS: CLEAN")
        print("   No anomalies were detected by any module.")
    else:
        print(f"❌ SYSTEM STATUS: INFECTED")
        print(f"   Detections found: {detections}")
        print("   Immediate action recommended!")

if __name__ == "__main__":
    run_full_scan()
