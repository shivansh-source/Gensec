import os
import subprocess
import json
import time
from github import Github, Auth, GithubException
from groq import Groq


# --- FILE CONFIGURATION ---
VULNERABLE_FILE_PATH = "vulnerable_app.go"
REPORT_FILE = "report.json"
FIXED_FILE_PATH = "fixed_app.go"


# --- API KEY CONFIGURATION ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_USERNAME = os.environ.get("GITHUB_USER")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")


# --- SCANNER ---
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
    """
    Run Semgrep with VALID rule sets only
    """
    print(f"🤖 (Scanner): Running Semgrep on {VULNERABLE_FILE_PATH}...")
    try:
        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

        # Use ONLY VALID Semgrep rule sets (removed invalid ones)
        scan_command = [
            "semgrep",
            "--config", "p/gosec",              # Go security - VALID ✅
            "--config", "p/owasp-top-ten",      # OWASP Top 10 - VALID ✅
            "--config", "p/security-audit",     # Security audit - VALID ✅
            "--config", "p/cwe-top-25",         # CWE Top 25 - VALID ✅
            "--json", "-o", REPORT_FILE,
            VULNERABLE_FILE_PATH
        ]

        result = subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8')

        # Check for errors in Semgrep output
        if result.returncode != 0 and "404" in result.stderr:
            print("⚠️  (Scanner): Some rule configs not found, retrying with minimal config...")
            # Fallback to just gosec
            scan_command = [
                "semgrep",
                "--config", "p/gosec",
                "--json", "-o", REPORT_FILE,
                VULNERABLE_FILE_PATH
            ]
            result = subprocess.run(scan_command, capture_output=True, text=True, encoding='utf-8')

        if not os.path.exists(REPORT_FILE) or os.path.getsize(REPORT_FILE) == 0:
            print("✅ (Scanner): Scan complete. No vulnerabilities found.")
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


# --- PARSER ---
def get_vulnerability_info():
    """
    Reads Semgrep report and returns the highest priority vulnerability as a dictionary.
    """
    print("🤖 (Parser): Reading Semgrep report...")
    try:
        with open(REPORT_FILE, 'r', encoding='utf-8') as f:
            report = json.load(f)

        if not report.get("results"):
            print("❌ (Parser): 'results' key missing or empty in report.")
            return None

        # Priority scoring based on keywords
        severity_keywords = {
            "command injection": 0,
            "sql injection": 1,
            "hardcoded": 2,
            "hardcoded secret": 2,
            "weak crypto": 3,
            "md5": 3,
            "tls": 4,
            "xss": 5,
            "sensitive": 6,
        }

        findings = []
        print(f"🤖 (Parser): Analyzing {len(report['results'])} findings...")

        for idx, finding in enumerate(report["results"]):
            check_id = finding.get("check_id", "unknown")
            message = finding.get("extra", {}).get("message", "Unknown issue")
            severity = finding.get("extra", {}).get("severity", "UNKNOWN")
            line = finding.get("start", {}).get("line", 0)
            snippet = finding.get("extra", {}).get("lines", "N/A")
            
            # Calculate priority based on keywords in message
            priority_score = 999
            for keyword, score in severity_keywords.items():
                if keyword.lower() in message.lower():
                    priority_score = score
                    break
            
            # Map severity to score
            severity_map = {"CRITICAL": -1, "HIGH": 0, "MEDIUM": 5, "LOW": 10, "WARNING": 6}
            severity_score = severity_map.get(severity, 999)
            
            # Use lower score (higher priority)
            final_priority = min(priority_score, severity_score)
            
            findings.append({
                "check_id": check_id,
                "message": message,
                "severity": severity,
                "line": line,
                "priority": final_priority,
                "snippet": snippet,
            })
            
            print(f"   [{idx+1}] {severity} | Line {line} | {check_id}")
            print(f"       Message: {message[:80]}...")

        if not findings:
            print("❌ (Parser): No findings extracted from report.")
            return None

        # Sort by priority (lower = higher priority)
        findings.sort(key=lambda x: x["priority"])
        best_finding = findings[0]
        
        print(f"\n✅ (Parser): Highest priority issue: '{best_finding['severity']}' - {best_finding['check_id']}")
        print(f"   Message: {best_finding['message']}")
        print(f"   Line: {best_finding['line']}")
        
        return best_finding

    except Exception as e:
        print(f"❌ (Parser): Error reading or parsing report.json: {e}")
        import traceback
        traceback.print_exc()
        return None


# --- FIXER ---
def run_fixer_agent(full_code, issue, snippet):
    """
    Sends vulnerability details to Groq to generate a fix.
    """
    if not GROQ_API_KEY:
        print("❌ (Fixer): GROQ_API_KEY environment variable not set.")
        return False

    print(f"🤖 (Fixer): Sending detailed prompt to Groq ({GROQ_MODEL})...")
    try:
        client = Groq(api_key=GROQ_API_KEY)
        
        prompt = f"""You are GenSec, an elite AI DevSecOps agent. Your mission is to fix a security vulnerability.
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
1. Analyze the full file and the specific vulnerability.
2. Fix *only* that one vulnerability.
3. Return the *ENTIRE* corrected Go file.

FULL FIXED CODE:"""

        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=GROQ_MODEL,
            max_tokens=4096,
            temperature=0.0,
        )

        fixed_code = chat_completion.choices[0].message.content.strip()
        
        print("✅ (Fixer): Fix generated by Groq!")

        if not fixed_code.startswith("package main"):
            print(f"⚠️ (Fixer): Warning - Groq fix might not be valid. Output: {fixed_code[:100]}...")

        with open(FIXED_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(fixed_code)
        print(f"✅ (Fixer): Fix saved locally to {FIXED_FILE_PATH}")
        return True
        
    except Exception as e:
        print(f"❌ (Fixer): Error connecting to Groq API: {e}")
        return False


# --- VERIFIER ---
def run_verifier(original_check_id):
    """
    Verifies that the fix actually resolved the vulnerability.
    """
    print(f"🤖 (Verifier): Verifying the fix for {original_check_id}...")
    VERIFY_REPORT_FILE = "verify_report.json"
    
    try:
        print(f"🤖 (Verifier): Re-running Semgrep on {FIXED_FILE_PATH}...")
        
        verify_command = [
            "semgrep",
            "--config", "p/gosec",
            "--config", "p/owasp-top-ten",
            "--config", "p/security-audit",
            "--config", "p/cwe-top-25",
            "--json", "-o", VERIFY_REPORT_FILE,
            FIXED_FILE_PATH
        ]
        
        subprocess.run(verify_command, capture_output=True, text=True, encoding='utf-8')

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
            print("🎉 (Verifier): Verification successful! The fix is good.")
            return True

    except Exception as e:
        print(f"❌ (Verifier): An unexpected error occurred during verification: {e}")
        return False


# --- PR CREATION ---
def create_github_pull_request(repo, original_file_sha, vuln_message):
    """
    Creates a Pull Request with the fixed code.
    """
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
        pr_body = f"""Hello! I am **GenSec**, your autonomous security agent.

I have detected, fixed, and verified a patch for the following vulnerability:
* **Issue:** `{vuln_message}`

This PR contains the automated fix. My verification step confirms that the original vulnerability is gone.

Please review and merge."""
        
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=new_branch_name,
            base=repo.default_branch
        )
        
        print(f"\n🎉🎉🎉 SUCCESS! Pull Request created! 🎉🎉🎉")
        print(f"View it here: {pr.html_url}")

    except Exception as e:
        print(f"❌ (GitHub): Error creating Pull Request: {e}")


# --- MAIN WORKFLOW ---
def main():
    if not GROQ_API_KEY:
        print("❌ (Main): GROQ_API_KEY not set. Halting workflow.")
        return
    
    print(f"ℹ️  (Main): Using Groq model: {GROQ_MODEL}")
    print(f"ℹ️  (Main): GenSec v2 - Enhanced vulnerability detection\n")

    repo, file_sha = fetch_code_from_github()
    
    if not repo or not file_sha:
        print("❌ (Main): Failed to fetch code from GitHub.")
        return

    if not run_scanner():
        print("🎉 Project is secure or scan failed to find issues.")
        return

    finding = get_vulnerability_info()
    
    if finding is None:
        print("❌ (Main): Parser failed to extract vulnerability information.")
        return
    
    try:
        with open(VULNERABLE_FILE_PATH, 'r', encoding='utf-8') as f:
            full_code = f.read()
    except Exception as e:
        print(f"❌ (Main): Error reading local vulnerable file: {e}")
        return

    vuln_message = finding['message']
    vuln_snippet = finding['snippet']
    vuln_id = finding['check_id']
    
    if not run_fixer_agent(full_code, vuln_message, vuln_snippet):
        print("❌ (Main): Fixer agent failed. Halting.")
        return

    if not run_verifier(vuln_id):
        print("❌ (Main): Verification failed! The fix was bad. Aborting PR creation.")
        return

    create_github_pull_request(repo, file_sha, vuln_message)


if __name__ == "__main__":
    main()