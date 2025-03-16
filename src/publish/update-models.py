'''Update threat models hash and dates'''

import sys
import hashlib
import json
import datetime


def open_threat_model(filename: str) -> None:
    '''Open the file in read mode and return the JSON'''
    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)
    return data


def save_threat_model(filename: str, data: dict) -> None:
    '''Open the file in write mode and save the JSON'''
    with open(filename, 'w', encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def hash_file(filename: str) -> str:
    '''Compute and returns the sha256 hash of the JSON'''
    h = hashlib.sha256()

    # Open the file in binary mode
    with open(filename, 'rb') as file:
        while True:
            # Read data from file
            data = file.read(65536)
            if not data:
                break
            # Update hash with data
            h.update(data)

    return h.hexdigest()


def verify_signature(filename: str, stored_signature: str) -> bool:
    '''Verify if the current signature matches the stored one
    
    Returns True if signature is valid (file hasn't changed)
    Returns False if signature is invalid (file has changed)
    '''
    # Save current data with empty signature to verify hash
    data = open_threat_model(filename)
    original_signature = data["signature"]
    data["signature"] = ""
    save_threat_model(filename, data)
    
    # Calculate hash
    calculated_hash = hash_file(filename)
    
    # Restore original signature
    data["signature"] = original_signature
    save_threat_model(filename, data)
    
    # Compare calculated hash with stored signature
    return calculated_hash == stored_signature


def update_threat_model_header(filename):
    '''Update the hash and date in the header of the threat model'''
    data = open_threat_model(filename)
    
    # Get the current signature
    current_signature = data.get("signature", "")
    
    # Check if signature is valid (file hasn't changed)
    if current_signature and verify_signature(filename, current_signature):
        print(f"Signature valid for {filename} - file hasn't changed, skipping update")
        return
    
    # File has changed or no signature exists, proceed with update
    print(f"Updating signature for {filename}")

    # Update the date
    data["date"] = datetime.datetime.now().strftime("%B %dth %Y")

    # Remove the signature to prepare hash computation
    data["signature"] = ""

    save_threat_model(filename, data)

    data = open_threat_model(filename)

    # Update with the new signature
    data["signature"] = hash_file(filename)

    save_threat_model(filename, data)

    # Save a .sig file with the signature (remove the .json extension)
    with open(filename.removesuffix(".json") + ".sig", "w") as file:
        file.write(data["signature"])


if __name__ == "__main__":
    for arg in sys.argv:
        if arg.endswith(".json"):
            print(f"Checking {arg}")
            update_threat_model_header(arg)
