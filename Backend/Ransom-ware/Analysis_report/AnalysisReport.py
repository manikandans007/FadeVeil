import os
import magic
import math
import json
from collections import Counter
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
TARGET_FOLDER = os.getenv("TARGET_FOLDER")

# Define output directory for analysis reports
REPORT_FOLDER = os.path.join("Ransom-ware", "Analysis_report")
RESULTS_FILE = os.path.join(REPORT_FOLDER, "result.json")

# Ensure the report folder exists
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Dictionary containing known ransomware extensions and their encryption methods
RANSOMWARE_SIGNATURES = {
    ".wcry": {"family": "WannaCry", "encryption": "AES-128 + RSA-2048"},
    ".locky": {"family": "Locky", "encryption": "RSA-2048 + AES-128"},
    ".cerber": {"family": "Cerber", "encryption": "AES-256"},
    ".crypt": {"family": "CryptXXX", "encryption": "AES-256 + RSA-4096"},
    ".ragnar": {"family": "Ragnar Locker", "encryption": "ChaCha20 + RSA-2048"},
    ".revil": {"family": "REvil (Sodinokibi)", "encryption": "AES-256 + RSA-4096"},
    ".ryuk": {"family": "Ryuk", "encryption": "AES-256 + RSA-4096"},
    ".phobos": {"family": "Phobos", "encryption": "AES-256 + RSA-2048"},
    ".djvu": {"family": "STOP (Djvu)", "encryption": "AES-256 + RSA-2048"},
}

# MIME types commonly associated with encrypted files
ENCRYPTED_MIME_TYPES = {
    "application/octet-stream",  # Generic binary files (often encrypted)
    "application/x-dosexec",  # Windows executable files
    "application/x-msdownload",  # Windows DLLs and executables
    "application/pgp-encrypted",  # PGP encrypted data
}

# MIME types that are generally considered safe (not encrypted)
SAFE_MIME_TYPES = {
    "text/plain", "text/html", "text/csv", "application/json",
    "image/jpeg", "image/png", "image/gif", "application/pdf",
    "application/zip", "application/x-tar", "image/webp",
    "application/xml", "application/javascript", "application/x-sh",
    "application/x-shellscript", "application/x-python",
    "application/x-perl", "application/x-php", "application/x-ruby",
    "application/x-c", "application/x-c++", "application/x-java",
    "application/x-go", "application/x-rust", "application/x-swift",
    "application/x-objectivec", "application/x-matlab",
    "application/x-lua", "application/x-sql", "application/x-yaml",
}

def calculate_entropy(file_path):
    """Calculate file entropy to determine randomness (high entropy suggests encryption)."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        
        if not data:
            return 0  # Return zero entropy for empty files
        
        counter = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
        
        return entropy
    except Exception as e:
        print(f"Error calculating entropy for {file_path}: {e}")
        return 0  # Return low entropy on failure

def analyze_file(file_path):
    """Analyze the file to detect potential ransomware encryption."""
    try:
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(file_path)[1].lower()
        file_mime = magic.Magic(mime=True).from_file(file_path)
        entropy = calculate_entropy(file_path)

        # Check if file has a known ransomware extension
        ransomware_details = RANSOMWARE_SIGNATURES.get(file_extension, {"family": "Unknown", "encryption": "Unknown"})

        # Determine if the file is encrypted
        is_encrypted = entropy >= 8 or file_mime in ENCRYPTED_MIME_TYPES

        # Classification based on encryption status
        if not is_encrypted:
            if file_mime in SAFE_MIME_TYPES:
                encryption_status = "Not Encrypted"
                ransomware_family = "Not Harmful"
            else:
                encryption_status = "Not Encrypted"
                ransomware_family = "Unknown"
        else:
            if ransomware_details["family"] == "Unknown":
                ransomware_family = "Possibly Encrypted File"
                encryption_status = "Unknown Encryption Method"
            else:
                ransomware_family = ransomware_details["family"]
                encryption_status = ransomware_details["encryption"]

        return {
            "name": os.path.basename(file_path),
            "size": f"{file_size} Bytes",
            "extension": file_extension,
            "mimeType": file_mime,
            "entropy": round(entropy, 2),
            "ransomware": ransomware_family,
            "encryption": encryption_status,
            "isEncrypted": "Yes" if is_encrypted else "No",
        }
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return {
            "name": os.path.basename(file_path),
            "size": "Error",
            "extension": "Error",
            "mimeType": "Error",
            "entropy": "Error",
            "ransomware": "Error",
            "encryption": "Error",
            "isEncrypted": "Error",
        }

def analyze_folder(target_folder):
    """Scan and analyze all files in the specified target folder."""
    if not os.path.exists(target_folder):
        return {"error": f"Folder '{target_folder}' not found!"}

    results = []
    for root, _, files in os.walk(target_folder):
        for file in files:
            file_path = os.path.join(root, file)
            results.append(analyze_file(file_path))

    return results

if __name__ == "__main__":
    if TARGET_FOLDER:
        report_results = analyze_folder(TARGET_FOLDER)
        
        # Save analysis results as a JSON report
        with open(RESULTS_FILE, "w") as f:
            json.dump(report_results, f, indent=4)
        
        print(json.dumps({"message": f"Analysis completed. Results saved to {RESULTS_FILE}"}))
    else:
        print(json.dumps({"error": "TARGET_FOLDER not found in .env file!"}))
