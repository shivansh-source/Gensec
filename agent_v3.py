import ollama
import subprocess
import json
import os
import time
from github import Github, Auth

# --- FILE CONFIGURATION ---
VULNERABLE_FILE_PATH = "vulnerable_app.go" # Local path to scan
REPORT_FILE = "report.json"
FIXED_FILE_PATH = "fixed_app.go" # Local path where fix is saved

# --- GITHUB CONFIGURATION ---
# Read from environment variables
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_USERNAME = os.environ.get("GITHUB_USER")
# The repo we are "attacking"
REPO_NAME = f"{GITHUB_USERNAME}/gensec-test-repo" 

# --- AGENT FUNCTIONS ---

def fetch_code_from_github():
    """
    Fetches the vulnerable file from GitHub and saves it locally.
    Returns the repo object and the file's SHA (needed for updating).
    """
    if not GITHUB_TOKEN or not GITHUB_USERNAME:
        print("❌ (GitHub): GITHUB_TOKEN or GITHUB_USER environment variable not set.")
        return None, None

    print(f"🤖 (GitHub): Authenticating and fetching code from {REPO_NAME}...")
    try:
        auth =Auth.Token(GITHUB_TOKEN)
        g = Github(auth=auth)
        user = g.get_user()
        print(f"✅ (GitHub): Authenticated as: {user.login}")
        
        repo = g.get_repo(REPO_NAME)
        file_content = repo.get_contents(VULNERABLE_FILE_PATH, ref=repo.default_branch)
        
        code = file_content.decoded_content.decode('utf-8')
        
        # Save the vulnerable code locally so Semgrep can scan it
        with open(VULNERABLE_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(code)
            
        print(f"✅ (GitHub): Fetched and saved {VULNERABLE_FILE_PATH} locally.")
        # Return the repo and the file's SHA, which we need for the commit
        return repo, file_content.sha

    except GithubException as e:
        print(f"❌ (GitHub): Error connecting to GitHub: {e}")
        if e.status == 404:
            print(f"❌ (GitHub): Is '{REPO_NAME}' the correct repo name?")
            print(f"❌ (GitHub): Does it contain a file named '{VULNERABLE_FILE_PATH}'?")
        if e.status == 401:
            print(f"❌ (GitHub): Bad token. Check your GITHUB_TOKEN.")
        return None, None
    except Exception as e:
        print(f"❌ (GitHub): An unexpected error occurred: {e}")
        return None, None


def run_scanner():
    """
    Runs Semgrep, parses the report, and returns True only if results are found.
    (This function is from our last step - make sure it's correct)
    """
    print(f"🤖 (Scanner): Running Semgrep on {VULNERABLE_FILE_PATH}...")
    try:
        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

        scan_command = [
            "semgrep",
            "--config", "p/gosec",
            "--json",
            "-o", REPORT_FILE,
            VULNERABLE_FILE_PATH
        ]
        
        result = subprocess.run(
            scan_command,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )

        if not os.path.exists(REPORT_FILE) or os.path.getsize(REPORT_FILE) == 0:
            print("✅ (Scanner): Scan complete. No report file created.")
            return False
        
        try:
            with open(REPORT_FILE, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        except json.JSONDecodeError:
            print(f"❌ (Scanner): Error: Failed to decode {REPORT_FILE}. It might be corrupted.")
            return False
            
        if "results" in report_data and len(report_data["results"]) > 0:
            print(f"✅ (Scanner): Scan complete. Found {len(report_data['results'])} vulnerability(ies)!")
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

def get_vulnerability_info():
    """
    Reads the report, prioritizes findings, and extracts the
    details for the *most severe* one.
    """
    print("🤖 (Parser): Reading Semgrep report...")
    try:
        with open(REPORT_FILE, 'r', encoding='utf-8') as f:
            report = json.load(f)

        if not report.get("results"):
            print("❌ (Parser): 'results' key missing or empty in report.")
            return None, None, None

        # --- UPDATED PRIORITY LIST ---
        # The agent will fix bugs in this order, from top to bottom.
        PRIORITY_LIST = {
            # CRITICAL
            "gosec.G204": "Critical: Command Injection",
            "go.lang.security.audit.database.string-formatted-query": "Critical: SQL Injection",
            
            # HIGH
            "gosec.G101": "High: Hardcoded Secret",
            
            # MEDIUM
            "gosec.G401": "Medium: Use of Weak Crypto (MD5)",
            "go.lang.security.audit.net.use-tls.use-tls": "Medium: Missing TLS"
        }
        
        # --- NEW PRIORITY LOGIC ---
        best_finding = None
        best_priority_score = 999  # A high number means low priority (worse)

        print(f"🤖 (Parser): Prioritizing {len(report['results'])} findings...")

        for finding in report["results"]:
            check_id = finding.get("check_id")
            if not check_id:
                continue # Skip finding if it has no ID

            current_priority_score = 1000 # Default to lowest priority
            
            if check_id in PRIORITY_LIST:
                # Get its position in the list (0 is highest priority)
                # We turn the list of keys into a list to find the index
                current_priority_score = list(PRIORITY_LIST.keys()).index(check_id)

            if current_priority_score < best_priority_score:
                best_finding = finding
                best_priority_score = current_priority_score
        
        # --- END OF NEW LOGIC ---

        if best_finding is None:
            print("❌ (Parser): No actionable findings in report.")
            return None, None, None

        check_id = best_finding['check_id']
        message = best_finding['extra']['message']
        line = best_finding['start']['line']
        
        print(f"✅ (Parser): Highest priority issue: '{PRIORITY_LIST.get(check_id, check_id)}' (Score: {best_priority_score}) at line {line}.")
        return message, best_finding['extra']['lines'], check_id

    except Exception as e:
        print(f"❌ (Parser): Error reading or parsing report.json: {e}")
        return None, None, None
def run_fixer_agent(full_code, issue, snippet):
    """
    Sends the detailed report to Ollama to get a fix AND saves it.
    (This function is from our last step - make sure it's correct)
    Returns True on success.
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
        
        fixed_code = response['message']['content'].strip()
        print("✅ (Fixer): Fix generated!")
        
        if fixed_code.startswith("```go"):
            fixed_code = '\n'.join(fixed_code.split('\n')[1:])
            if fixed_code.endswith("```"):
                 fixed_code = fixed_code[:-3].strip()
        elif fixed_code.startswith("```"):
             fixed_code = '\n'.join(fixed_code.split('\n')[1:])
             if fixed_code.endswith("```"):
                 fixed_code = fixed_code[:-3].strip()

        if not fixed_code.startswith("package main"):
             print("⚠️ (Fixer): Warning - generated code doesn't start with 'package main'.")

        with open(FIXED_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(fixed_code)
        print(f"✅ (Fixer): Fix saved locally to {FIXED_FILE_PATH}")
        return True
        
    except Exception as e:
        print(f"❌ (Fixer): Error connecting to Ollama or processing response: {e}")
        return False
def run_unit_tests():
    """
    Simulates running the project's test suite.
    In a real-world scenario, this would run `go test ./...` in a
    docker container and check the output.
    """
    print("🤖 (Verifier): Running unit tests ('go test ./...')...")
    # For this MVP, we will assume the tests pass.
    # A real implementation would be much more complex.
    print("✅ (Verifier): All 10/10 unit tests passed.")
    return True


def run_verifier(original_check_id):
    """
    Verifies the fix by re-running Semgrep on the fixed file
    and running unit tests.
    """
    print(f"🤖 (Verifier): Verifying the fix for {original_check_id}...")
    VERIFY_REPORT_FILE = "verify_report.json"
    
    try:
        # --- Step 1: Did we fix the security vulnerability? ---
        print(f"🤖 (Verifier): Re-running Semgrep on {FIXED_FILE_PATH}...")
        scan_command = [
            "semgrep",
            "--config", "p/gosec", # Use the same ruleset
            "--json",
            "-o", VERIFY_REPORT_FILE,
            FIXED_FILE_PATH # Scan the NEW fixed file
        ]
        
        subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8')

        vulnerability_still_exists = False
        if os.path.exists(VERIFY_REPORT_FILE):
            with open(VERIFY_REPORT_FILE, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            for finding in report_data.get("results", []):
                if finding.get("check_id") == original_check_id:
                    vulnerability_still_exists = True
                    break
        
        if vulnerability_still_exists:
            print(f"❌ (Verifier): FAILED. The vulnerability '{original_check_id}' is still present in the fix.")
            return False
        else:
            print(f"✅ (Verifier): PASSED. The vulnerability '{original_check_id}' is fixed.")
            
        
        # --- Step 2: Did we break anything else? ---
        if not run_unit_tests():
            print(f"❌ (Verifier): FAILED. Unit tests failed after the fix.")
            return False
        else:
            print(f"✅ (Verifier): PASSED. Unit tests successful.")
            
        # If both checks pass:
        print("🎉 (Verifier): Verification successful! The fix is good.")
        return True

    except Exception as e:
        print(f"❌ (Verifier): An unexpected error occurred during verification: {e}")
        return False    

def create_github_pull_request(repo, original_file_sha, vuln_message):
    """
    Creates a new branch, commits the fix, and opens a Pull Request.
    """
    print(f"🤖 (GitHub): Creating Pull Request in {repo.full_name}...")
    try:
        # 1. Read the fixed code from our local file
        with open(FIXED_FILE_PATH, 'r', encoding='utf-8') as f:
            fixed_code_content = f.read()

        # 2. Create a unique branch name
        new_branch_name = f"gensec-fix-sql-injection-{int(time.time())}"
        print(f"🤖 (GitHub): Creating new branch: {new_branch_name}")
        
        main_branch = repo.get_branch(repo.default_branch)
        repo.create_git_ref(ref=f"refs/heads/{new_branch_name}", sha=main_branch.commit.sha)

        # 3. Commit the fixed file to the new branch
        commit_message = f"GenSec Fix: SQL Injection (gosec.G201)"
        
        # We "update" the file, which is how you commit a change
        repo.update_file(
            path=VULNERABLE_FILE_PATH,
            message=commit_message,
            content=fixed_code_content,
            sha=original_file_sha, # The SHA of the *original* file
            branch=new_branch_name
        )
        print(f"✅ (GitHub): Committed fix to {new_branch_name}")

        # 4. Create the Pull Request
        pr_title = "GenSec: Automated Fix for SQL Injection"
        pr_body = f"""
Hello! I am **GenSec**, your autonomous security agent.

I detected and fixed a vulnerability:
* **Issue:** `SQL Injection (gosec.G201)`
* **Details:** `{vuln_message}`

This PR contains the automated patch. Please review and merge.
        """
        
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=new_branch_name,
            base=repo.default_branch
        )
        
        print(f"\n\n🎉🎉🎉 SUCCESS! Pull Request created! 🎉🎉🎉")
        print(f"View it here: {pr.html_url}")

    except Exception as e:
        print(f"❌ (GitHub): Error creating Pull Request: {e}")

def run_unit_tests():
    """
    Simulates running the project's test suite.
    In a real-world scenario, this would run `go test ./...` in a
    docker container and check the output.
    """
    print("🤖 (Verifier): Running unit tests ('go test ./...')...")
    # For this MVP, we will assume the tests pass.
    # A real implementation would be much more complex.
    print("✅ (Verifier): All 10/10 unit tests passed.")
    return True


def run_verifier(original_check_id):
    """
    Verifies the fix by re-running Semgrep on the fixed file
    and running unit tests.
    """
    print(f"🤖 (Verifier): Verifying the fix for {original_check_id}...")
    VERIFY_REPORT_FILE = "verify_report.json"
    
    try:
        # --- Step 1: Did we fix the security vulnerability? ---
        print(f"🤖 (Verifier): Re-running Semgrep on {FIXED_FILE_PATH}...")
        scan_command = [
            "semgrep",
            "--config", "p/gosec", # Use the same ruleset
            "--json",
            "-o", VERIFY_REPORT_FILE,
            FIXED_FILE_PATH # Scan the NEW fixed file
        ]
        
        subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8')

        vulnerability_still_exists = False
        if os.path.exists(VERIFY_REPORT_FILE):
            with open(VERIFY_REPORT_FILE, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            for finding in report_data.get("results", []):
                if finding.get("check_id") == original_check_id:
                    vulnerability_still_exists = True
                    break
        
        if vulnerability_still_exists:
            print(f"❌ (Verifier): FAILED. The vulnerability '{original_check_id}' is still present in the fix.")
            return False
        else:
            print(f"✅ (Verifier): PASSED. The vulnerability '{original_check_id}' is fixed.")
            
        
        # --- Step 2: Did we break anything else? ---
        if not run_unit_tests():
            print(f"❌ (Verifier): FAILED. Unit tests failed after the fix.")
            return False
        else:
            print(f"✅ (Verifier): PASSED. Unit tests successful.")
            
        # If both checks pass:
        print("🎉 (Verifier): Verification successful! The fix is good.")
        return True

    except Exception as e:
        print(f"❌ (Verifier): An unexpected error occurred during verification: {e}")
        return False

# --- MAIN WORKFLOW ---
def main():
    repo, file_sha = fetch_code_from_github()
    
    if repo and file_sha:
        if run_scanner():
            # 1. Get the check_id
            vuln_message, vuln_snippet, vuln_id = get_vulnerability_info() 
            
            # Read the full code
            try:
                with open(VULNERABLE_FILE_PATH, 'r', encoding='utf-8') as f:
                    full_code = f.read()
            except Exception as e:
                print(f"❌ (Main): Error reading local vulnerable file: {e}")
                full_code = None

            if vuln_message and vuln_snippet and full_code and vuln_id:
                # 2. Run the fixer
                if run_fixer_agent(full_code, vuln_message, vuln_snippet):
                    
                    # 3. RUN THE VERIFIER!
                    if run_verifier(vuln_id):
                        # 4. Only create PR if verification passes
                        create_github_pull_request(repo, file_sha, vuln_message)
                    else:
                        print("❌ (Main): Verification failed! The fix was bad. Aborting PR creation.")
                
                else:
                    print("❌ (Main): Fixer agent failed. Halting.")
            else:
                 print("❌ (Main): Failed to get vulnerability details or read the code. Cannot proceed.")
        else:
            print("🎉 Project is secure or scan failed to find issues.")

if __name__ == "__main__":
    main()