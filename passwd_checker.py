import re
import hashlib
import requests

# check basic strength of the password
def check_strength(password):
    checks = {
        "length": len(password) >= 8,
        "upper": re.search(r"[A-Z]", password) is not None,
        "lower": re.search(r"[a-z]", password) is not None,
        "digit": re.search(r"[0-9]", password) is not None,
        "special": re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None
    }

    score = sum(checks.values())
    if score == 5:
        status = "Strong"
    elif score >= 3:
        status = "Medium"
    else:
        status = "Weak"

    return status, checks

# check if password has appeared in breaches (using HIBP API)
def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        return "Could not check breach (API error)."

    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"⚠️ This password has been seen {count} times in data breaches."
    return "✅ Not found in known breaches."

if __name__ == "__main__":
    print("=== Password Strength & Breach Checker ===\n")
    pwd = input("Enter password to check: ")

    verdict, details = check_strength(pwd)
    print("\nStrength Check:", verdict)
    print("Details:", details)

    print("\nBreach Check:")
    print(check_breach(pwd))
