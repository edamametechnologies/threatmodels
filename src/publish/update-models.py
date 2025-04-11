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
        json.dump(data, file, indent=2, ensure_ascii=False, sort_keys=True)


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
    # Load data from file
    data = open_threat_model(filename)
    
    # Create a copy for calculating signature
    data_copy = data.copy()
    data_copy["signature"] = ""
    
    # Calculate hash
    json_str = json.dumps(data_copy, sort_keys=True)
    calculated_hash = hashlib.sha256(json_str.encode()).hexdigest()
    
    # Compare calculated hash with stored signature
    return calculated_hash == stored_signature


def update_threat_model_header(filename):
    '''Update the hash and date in the header of the threat model'''
    data = open_threat_model(filename)
    
    # Get the current signature
    current_signature = data.get("signature", "")
    
    # Create a copy for calculating the new signature
    data_copy = data.copy()
    data_copy["signature"] = ""
    
    # Calculate new signature by serializing JSON (same method as in validate-models.py)
    json_str = json.dumps(data_copy, sort_keys=True)
    new_signature = hashlib.sha256(json_str.encode()).hexdigest()
    
    # If signatures match (content hasn't changed), don't update the date
    if current_signature and current_signature == new_signature:
        print(f"Content unchanged for {filename} - keeping original date")
    else:
        # Content has changed or no previous signature exists, update the date
        print(f"Content changed for {filename} - updating date and signature")
        data["date"] = datetime.datetime.now().strftime("%B %dth %Y")
    
    # Always update the signature to ensure it's correct
    data["signature"] = new_signature
    save_threat_model(filename, data)
    
    # Save a .sig file with the signature (remove the .json extension)
    with open(filename.removesuffix(".json") + ".sig", "w") as file:
        file.write(data["signature"])


if __name__ == "__main__":
    for arg in sys.argv:
        if arg.endswith(".json"):
            print(f"Checking {arg}")
            update_threat_model_header(arg)
