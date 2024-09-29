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
