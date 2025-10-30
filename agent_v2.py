import ollama
import subprocess
import json
import os

# --- FILE CONFIGURATION ---
VULNERABLE_FILE = "vulnerable_app.go"
REPORT_FILE = "report.json"
FIXED_FILE = "fixed_app.go"

def run_scanner():
    """
    Runs Semgrep, parses the report, and returns True only if results are found.
    """
    print(f"🤖 (Scanner): Running Semgrep on {VULNERABLE_FILE}...")
    try:
        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

        scan_command = [
            "semgrep",
            "--config", "p/gosec",
            "--json",
            "-o", REPORT_FILE,
            VULNERABLE_FILE
        ]
        
        # FIX 1: Add encoding='utf-8' to handle special characters
        result = subprocess.run(
            scan_command,
            capture_output=True,
            text=True,
            encoding='utf-8' # <-- ADDED THIS LINE
        )

        # --- DEBUGGING BLOCK ---
        print("\n--- SEMGREP DEBUG OUTPUT ---")
        if result.stdout:
            print("STDOUT:", result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr.strip()) 
        print("--- END DEBUG OUTPUT ---\n")
        # --- END DEBUGGING BLOCK ---

        if not os.path.exists(REPORT_FILE) or os.path.getsize(REPORT_FILE) == 0:
            print("✅ (Scanner): Scan complete. No report file created.")
            return False
        
        try:
            with open(REPORT_FILE, 'r', encoding='utf-8') as f: # Also add encoding here for reading
                report_data = json.load(f)
        except json.JSONDecodeError:
            print(f"❌ (Scanner): Error: Failed to decode {REPORT_FILE}. It might be corrupted.")
            return False
            
        if "results" in report_data and len(report_data["results"]) > 0:
            print(f"✅ (Scanner): Scan complete. Found {len(report_data['results'])} vulnerability(ies)!") # Changed message slightly
            return True
        else:
            print("✅ (Scanner): Scan complete. Report file was created, but no vulnerabilities listed.")
            return False

    except FileNotFoundError:
        print("❌ (Scanner): Error: 'semgrep' command not found. Make sure it's in your PATH.")
        return False
    except Exception as e:
        print(f"❌ (Scanner): An unexpected error occurred during scan: {e}")
        return False

# --- Make sure this function exists exactly like this ---
def get_vulnerability_info():
    """
    Reads the report and extracts the code, line number, and message of the FIRST finding.
    """
    print("🤖 (Parser): Reading Semgrep report...")
    try:
        with open(REPORT_FILE, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        # Get the first vulnerability found
        finding = report['results'][0] # Will only work if results list is not empty
        
        message = finding['extra']['message']
        line = finding['start']['line']
        code_snippet = finding['extra']['lines']
        
        print(f"✅ (Parser): Found issue: '{message}' at line {line}.")
        return message, code_snippet

    except IndexError:
         print(f"❌ (Parser): Error - Semgrep found issues, but the 'results' list in {REPORT_FILE} is empty.")
         return None, None
    except KeyError as e:
         print(f"❌ (Parser): Error parsing {REPORT_FILE}. Missing expected key: {e}")
         return None, None
    except Exception as e:
        print(f"❌ (Parser): Error reading or parsing report.json: {e}")
        return None, None
# --- End of get_vulnerability_info ---

def get_full_code():
    """Reads the entire vulnerable file."""
    try:
        with open(VULNERABLE_FILE, 'r', encoding='utf-8') as f: # Add encoding here too
            return f.read()
    except Exception as e:
        print(f"❌ (Reader): Error reading {VULNERABLE_FILE}: {e}")
        return None

def run_fixer_agent(full_code, issue, snippet):
    """
    Sends the detailed report to Ollama to get a fix.
    """
    print(f"🤖 (Fixer): Sending detailed prompt to Ollama...")
    prompt = f"""
You are a GenSec Agent, a senior Go security engineer.
Your mission is to fix a vulnerability that has been detected.
IMPORTANT: You must provide the *ENTIRE* fixed Go file, including all
original 'package' and 'import' statements. Do not just send a function snippet.

THE VULNERABILITY:
A Semgrep scan found this issue: "{issue}"
It occurred in this code snippet:
---
{snippet}
---

THE FULL VULNERABLE FILE:
---
{full_code}
---

Your task:
1.  Analyze the full file and the vulnerability.
2.  Fix the vulnerability by using parameterized queries (`db.Query(query, userID)`).
3.  Return the *ENTIRE* corrected Go file, starting from `package main`. Ensure all original imports are present.

FULL FIXED CODE:
"""
    try:
        response = ollama.chat(
            model='codellama',
            messages=[{'role': 'user', 'content': prompt}],
            options={'temperature': 0.0}
        )
        
        fixed_code = response['message']['content'].strip() # Add strip()
        print("✅ (Fixer): Fix generated!")
        
        # Clean up common markdown fences
        if fixed_code.startswith("```go"):
            fixed_code = '\n'.join(fixed_code.split('\n')[1:]) # Remove first line
            if fixed_code.endswith("```"):
                 fixed_code = fixed_code[:-3].strip() # Remove last line
        elif fixed_code.startswith("```"):
             fixed_code = '\n'.join(fixed_code.split('\n')[1:]) # Remove first line
             if fixed_code.endswith("```"):
                 fixed_code = fixed_code[:-3].strip() # Remove last line

        # Ensure the file starts correctly (basic check)
        if not fixed_code.startswith("package main"):
             print("⚠️ (Fixer): Warning - generated code doesn't start with 'package main'. Check the output.")
             # Add 'package main' if totally missing, but this might indicate bigger issues
             # if not fixed_code.strip().startswith("package"):
             #    fixed_code = "package main\n\n" + fixed_code

        with open(FIXED_FILE, 'w', encoding='utf-8') as f: # Add encoding
            f.write(fixed_code)
        print(f"✅ (Fixer): Fix saved to {FIXED_FILE}")
        
    except Exception as e:
        print(f"❌ (Fixer): Error connecting to Ollama or processing response: {e}")

# --- MAIN WORKFLOW ---
# FIX 2: Make sure this main function is exactly like this
def main():
    if run_scanner():
        # Make sure the function call matches the definition name
        vuln_message, vuln_snippet = get_vulnerability_info() 
        full_code = get_full_code()
        
        if vuln_message and vuln_snippet and full_code:
            run_fixer_agent(full_code, vuln_message, vuln_snippet)
        else:
             print("❌ (Main): Failed to get vulnerability details or read the code. Cannot proceed.")
    else:
        print("🎉 Project is secure or scan failed to find issues.")

if __name__ == "__main__":
    main()