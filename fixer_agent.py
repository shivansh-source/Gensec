import ollama

# 1. Read the vulnerable code
try:
    with open('vulnerable_app.go', 'r') as f:
        vulnerable_code = f.read()
except FileNotFoundError:
    print("Error: 'vulnerable_app.go' not found.")
    exit()

# 2. Create the prompt (same as before)
# We can be more explicit with instructions for local models.
prompt = f"""
You are a GenSec Agent, a world-class Go and DevSecOps expert.
Your mission is to find and fix security vulnerabilities.

A file has been flagged for a potential SQL Injection vulnerability.
Analyze the following Go code, identify the SQL injection, and provide *only* the fixed, secure version of the code.
The fix should use parameterized queries.

VULNERABLE CODE:
---
{vulnerable_code}
---

FIXED CODE:
"""

print("🤖 GenSec agent is thinking... (using local 'codellama' model)")

# 3. Send the request to the LOCAL model
try:
    # This connects to the Ollama app running on your machine
    response = ollama.chat(
        model='codellama',  # The model we downloaded
        messages=[
            {'role': 'user', 'content': prompt}
        ],
        options={
            'temperature': 0.0
        }
    )

    # 4. Get the fixed code back
    fixed_code = response['message']['content']

    print("\n\n✅ Agent has generated a fix!")
    print("---------------------------------")
    print(fixed_code)

    # 5. Save the fix
    with open('fixed_app.go', 'w') as f:
        # Clean up the output if the model adds markdown
        if fixed_code.startswith("```go"):
            fixed_code = fixed_code.split("\n", 1)[1]
            fixed_code = fixed_code.rsplit("```", 1)[0]
        
        f.write(fixed_code)
    
    print("\n\nSaved the patch to 'fixed_app.go'")

except Exception as e:
    print(f"An error occurred. Is Ollama running? Error: {e}")