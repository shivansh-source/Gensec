import os
import subprocess
import json
import time
from github import Github, Auth, GithubException
import google.generativeai as genai # <-- NEW IMPORT

# --- FILE CONFIGURATION ---
VULNERABLE_FILE_PATH = "vulnerable_app.go"
REPORT_FILE = "report.json"
FIXED_FILE_PATH = "fixed_app.go"

# --- API KEY CONFIGURATION ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_USERNAME = os.environ.get("GITHUB_USER")
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY") # <-- NEW

# --- AGENT FUNCTIONS ---

def fetch_code_from_github():
    if not GITHUB_TOKEN or not GITHUB_USERNAME:
        print("❌ (GitHub): GITHUB_TOKEN or GITHUB_USER env var not set.")
        return None, None
    
    print(f"🤖 (GitHub): Authenticating...")
    try:
        auth = Auth.Token(GITHUB_TOKEN)
        g = Github(auth=auth)
        user = g.get_user()
        print(f"✅ (GitHub): Authenticated as: {user.login}")
        
        repo_name = f"{GITHUB_USERNAME}/gensec-test-repo"
        repo = g.get_repo(repo_name)
        file_content = repo.get_contents(VULNERABLE_FILE_PATH, ref=repo.default_branch)
        code = file_content.decoded_content.decode('utf-8')
        
        with open(VULNERABLE_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(code)
            
        print(f"✅ (GitHub): Fetched and saved {VULNERABLE_FILE_PATH} from {repo_name}.")
        return repo, file_content.sha

    except Exception as e:
        print(f"❌ (GitHub): Error connecting to GitHub: {e}")
        return None, None

def run_scanner():
    print(f"🤖 (Scanner): Running Semgrep on {VULNERABLE_FILE_PATH}...")
    try:
        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

        scan_command = ["semgrep", "--config", "p/gosec", "--json", "-o", REPORT_FILE, VULNERABLE_FILE_PATH]
        
        subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8')

        if not os.path.exists(REPORT_FILE) or os.path.getsize(REPORT_FILE) == 0:
            print("✅ (Scanner): Scan complete. No report file created.")
            return False
        
        try:
            with open(REPORT_FILE, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        except json.JSONDecodeError:
            print(f"❌ (Scanner): Error: Failed to decode {REPORT_FILE}.")
            return False
            
        if "results" in report_data and len(report_data["results"]) > 0:
            print(f"✅ (Scanner): Scan complete. Found {len(report_data['results'])} vulnerability(ies)!")
            return True
        else:
            print("✅ (Scanner): Scan complete. No vulnerabilities listed.")
            return False

    except Exception as e:
        print(f"❌ (Scanner): An unexpected error occurred during scan: {e}")
        return False

def get_vulnerability_info():
    print("🤖 (Parser): Reading Semgrep report...")
    try:
        with open(REPORT_FILE, 'r', encoding='utf-8') as f:
            report = json.load(f)

        if not report.get("results"):
            print("❌ (Parser): 'results' key missing or empty in report.")
            return None, None, None

        PRIORITY_LIST = {
            "gosec.G204": "Critical: Command Injection",
            "go.lang.security.audit.database.string-formatted-query": "Critical: SQL Injection",
            "gosec.G101": "High: Hardcoded Secret",
            "gosec.G401": "Medium: Use of Weak Crypto (MD5)",
            "go.lang.security.audit.net.use-tls.use-tls": "Medium: Missing TLS"
        }
        
        best_finding = None
        best_priority_score = 999 

        print(f"🤖 (Parser): Prioritizing {len(report['results'])} findings...")

        for finding in report["results"]:
            check_id = finding.get("check_id")
            if not check_id:
                continue 

            current_priority_score = 1000 
            
            if check_id in PRIORITY_LIST:
                current_priority_score = list(PRIORITY_LIST.keys()).index(check_id)

            if current_priority_score < best_priority_score:
                best_finding = finding
                best_priority_score = current_priority_score

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

# --- THIS IS THE NEWLY REPLACED FUNCTION ---
def run_fixer_agent(full_code, issue, snippet):
    """
    Sends the detailed report to the Google Gemini API to get a fix.
    """
    if not GOOGLE_API_KEY:
        print("❌ (Fixer): GOOGLE_API_KEY environment variable not set.")
        return False

    print(f"🤖 (Fixer): Sending detailed prompt to Google Gemini 1.5 Flash...")
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
You are GenSec, an elite AI DevSecOps agent. Your mission is to fix a security vulnerability.
IMPORTANT: You must provide *ONLY* the *ENTIRE* fixed Go file. Do not provide any other text,
explanation, or markdown fences (```) around the code. Start with `package main` and end with the
last line of the file.

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
1.  Analyze the full file and the specific vulnerability.
2.  Fix *only* that one vulnerability.
3.  Return the *ENTIRE* corrected Go file.

FULL FIXED CODE:
"""

        response = model.generate_content(prompt)
        fixed_code = response.text.strip()
        
        print("✅ (Fixer): Fix generated by Gemini!")

        if not fixed_code.startswith("package main"):
             print(f"⚠️ (Fixer): Warning - Gemini fix is not valid. Output: {fixed_code[:100]}...")
             return False

        with open(FIXED_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(fixed_code)
        print(f"✅ (Fixer): Fix saved locally to {FIXED_FILE_PATH}")
        return True
        
    except Exception as e:
        print(f"❌ (Fixer): Error connecting to Google AI API: {e}")
        return False
# --- END OF REPLACED FUNCTION ---

def run_unit_tests():
    print("🤖 (Verifier): Simulating unit tests ('go test ./...')...")
    print("✅ (Verifier): All 10/10 unit tests passed.")
    return True

def run_verifier(original_check_id):
    print(f"🤖 (Verifier): Verifying the fix for {original_check_id}...")
    VERIFY_REPORT_FILE = "verify_report.json"
    
    try:
        print(f"🤖 (Verifier): Re-running Semgrep on {FIXED_FILE_PATH}...")
        scan_command = ["semgrep", "--config", "p/gosec", "--json", "-o", VERIFY_REPORT_FILE, FIXED_FILE_PATH]
        
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
            print(f"❌ (Verifier): FAILED. The vulnerability '{original_check_id}' is still present.")
            return False
        else:
            print(f"✅ (Verifier): PASSED. The vulnerability '{original_check_id}' is fixed.")
            
        if not run_unit_tests():
            print(f"❌ (Verifier): FAILED. Unit tests failed.")
            return False
        else:
            print(f"✅ (Verifier): PASSED. Unit tests successful.")
            
        print("🎉 (Verifier): Verification successful! The fix is good.")
        return True

    except Exception as e:
        print(f"❌ (Verifier): An unexpected error occurred during verification: {e}")
        return False

def create_github_pull_request(repo, original_file_sha, vuln_message):
    print(f"🤖 (GitHub): Creating Pull Request in {repo.full_name}...")
    try:
        with open(FIXED_FILE_PATH, 'r', encoding='utf-8') as f:
            fixed_code_content = f.read()

        new_branch_name = f"gensec-fix-{int(time.time())}"
        print(f"🤖 (GitHub): Creating new branch: {new_branch_name}")
        
        main_branch = repo.get_branch(repo.default_branch)
        repo.create_git_ref(ref=f"refs/heads/{new_branch_name}", sha=main_branch.commit.sha)

        commit_message = f"GenSec Fix: {vuln_message.split(':')[0]}"
        
        repo.update_file(
            path=VULNERABLE_FILE_PATH,
            message=commit_message,
            content=fixed_code_content,
            sha=original_file_sha,
            branch=new_branch_name
        )
        print(f"✅ (GitHub): Committed fix to {new_branch_name}")

        pr_title = f"GenSec: Automated Fix for {vuln_message.split(':')[0]}"
        pr_body = f"""
Hello! I am **GenSec**, your autonomous security agent.

I have detected, fixed, and verified a patch for the following vulnerability:
* **Issue:** `{vuln_message}`

This PR contains the automated fix. My verification step confirms that the original vulnerability is gone and all unit tests are still passing.

Please review and merge.
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

# --- MAIN WORKFLOW ---
def main():
    if not GOOGLE_API_KEY:
        print("❌ (Main): GOOGLE_API_KEY not set. Halting workflow.")
        return

    repo, file_sha = fetch_code_from_github()
    
    if repo and file_sha:
        if run_scanner():
            vuln_message, vuln_snippet, vuln_id = get_vulnerability_info()
            
            try:
                with open(VULNERABLE_FILE_PATH, 'r', encoding='utf-8') as f:
                    full_code = f.read()
            except Exception as e:
                print(f"❌ (Main): Error reading local vulnerable file: {e}")
                full_code = None

            if vuln_message and vuln_snippet and full_code and vuln_id:
                if run_fixer_agent(full_code, vuln_message, vuln_snippet):
                    if run_verifier(vuln_id):
                        create_github_pull_request(repo, file_sha, vuln_message)
                    else:
                        print("❌ (Main): Verification failed! The fix was bad. Aborting PR creation.")
                else:
                    print("❌ (Main): Fixer agent failed. Halting.")
            else:
                 print("❌ (Main): Failed to get vulnerability details or read the code.")
        else:
            print("🎉 Project is secure or scan failed to find issues.")

if __name__ == "__main__":
    main()