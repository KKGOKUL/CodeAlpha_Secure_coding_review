##SECURE CODING REVIEW##

Choose a programming language and application.
Review the code for security vulnerabilities and
provide recommendations for secure coding practices.
Use tools like static code analyzers or manual code
review


Tool used - ##Bandit##

**Bandit is a security tool designed to identify common security issues in
Python code. It is primarily used for static code analysis, scanning Python codebases 
for potential vulnerabilities, weaknesses, or bad coding practices.**

##OUR PYTHON PROGRM##

import hashlib
import subprocess

# Hardcoded password (this will be flagged by Bandit)
PASSWORD = "super_secret_password"

# Insecure usage of eval() (this will be flagged by Bandit)
def execute_command(user_input):
    eval(user_input)  # Dangerous, allows arbitrary code execution

# Weak hash algorithm (md5, sha1 will be flagged by Bandit)
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# Weak hash algorithm (sha1 will be flagged by Bandit)
def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()


"""
Vulnerabilities in This Code:
Hardcoded Password: Storing sensitive information like passwords in the code is a bad practice.
eval(): Using eval() on user input can lead to code injection vulnerabilities.
Weak Hashing Algorithms (md5, sha1): These are outdated and vulnerable to collision attacks.
Shell Injection: The subprocess.run() function with shell=True can allow arbitrary commands to be executed if unchecked user input is passed.
"""
___________________________________________________________________________________________________________________________________________________________
##How to Install Bandit##
 
  **pip install bandit**

##How to run this tool##

  **bandit -r your_python_name.py**
