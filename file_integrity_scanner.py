import hashlib
import os

print("=== DecodeLabs Task 5: Advanced File Integrity Scanner ===")

file_path = input("Enter file path: ").strip()

dangerous_extensions = [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".ps1", ".jar", ".msi", ".iso", ".html"]
suspicious_keywords = [b"password", b"token", b"cmd.exe", b"powershell", b"eval", b"base64", b"download"]

try:
    if not os.path.exists(file_path):
        print("Error: File not found.")
        exit()

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    extension = os.path.splitext(file_name)[1].lower()

    with open(file_path, "rb") as file:
        data = file.read()

    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

    risk_score = 0
    red_flags = []

    if extension in dangerous_extensions:
        risk_score += 4
        red_flags.append(f"Dangerous file extension detected: {extension}")

    if file_size > 10 * 1024 * 1024:
        risk_score += 2
        red_flags.append("File size is large and should be reviewed carefully.")

    for keyword in suspicious_keywords:
        if keyword.lower() in data.lower():
            risk_score += 2
            red_flags.append(f"Suspicious keyword found inside file: {keyword.decode(errors='ignore')}")

    old_hash = input("Enter old SHA-256 hash to compare or press Enter to skip: ").strip()

    if old_hash:
        if old_hash == sha256_hash:
            integrity_result = "File integrity verified. No change detected."
        else:
            integrity_result = "Warning! File hash mismatch. File may be modified."
            risk_score += 5
            red_flags.append("SHA-256 hash mismatch detected.")
    else:
        integrity_result = "No old hash provided. New hash generated."

    print("\n========== FILE SECURITY REPORT ==========")
    print("File Name:", file_name)
    print("File Size:", file_size, "bytes")
    print("Extension:", extension)
    print("\nMD5:", md5_hash)
    print("SHA-1:", sha1_hash)
    print("SHA-256:", sha256_hash)
    print("\nIntegrity Result:", integrity_result)
    print("Risk Score:", risk_score)

    if risk_score >= 8:
        status = "High Risk"
        action = "Do not execute. Escalate for malware analysis."
    elif risk_score >= 4:
        status = "Suspicious"
        action = "Review before opening."
    else:
        status = "Low Risk"
        action = "File appears safe based on basic checks."

    print("Status:", status)
    print("Recommended Action:", action)

    print("\nRed Flags:")
    if red_flags:
        for i, flag in enumerate(red_flags, 1):
            print(f"{i}. {flag}")
    else:
        print("No major red flags found.")

except PermissionError:
    print("Error: Permission denied. Try another file.")
except Exception as e:
    print("Error:", e)