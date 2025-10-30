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
    Reads the report and extracts the code, line number, and message of the FIRST finding.
    (This function is from our last step - make sure it's correct)
    """
    print("🤖 (Parser): Reading Semgrep report...")
    try:
        with open(REPORT_FILE, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        finding = report['results'][0] 
        
        message = finding['extra']['message']
        line = finding['start']['line']
        code_snippet = finding['extra']['lines']
        
        print(f"✅ (Parser): Found issue: '{message}' at line {line}.")
        return message, code_snippet

    except Exception as e:
        print(f"❌ (Parser): Error reading or parsing report.json: {e}")
        return None, None

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

# --- MAIN WORKFLOW ---
def main():
    repo, file_sha = fetch_code_from_github()
    
    if repo and file_sha:
        if run_scanner():
            vuln_message, vuln_snippet = get_vulnerability_info() 
            
            # Need to get the full code *we downloaded*
            with open(VULNERABLE_FILE_PATH, 'r', encoding='utf-8') as f:
                full_code = f.read()
            
            if vuln_message and vuln_snippet and full_code:
                if run_fixer_agent(full_code, vuln_message, vuln_snippet):
                    # We have a fix, now create the PR
                    create_github_pull_request(repo, file_sha, vuln_message)
                else:
                    print("❌ (Main): Fixer agent failed. Halting.")
            else:
                 print("❌ (Main): Failed to get vulnerability details or read the code. Cannot proceed.")
        else:
            print("🎉 Project is secure or scan failed to find issues.")

if __name__ == "__main__":
    main()