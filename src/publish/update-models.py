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


def update_threat_model_header(filename):
    '''Update the hash and date in the header of the threat model'''
    data = open_threat_model(filename)

    # Update the date
    data["date"] = datetime.datetime.now().strftime("%B %dth %Y")
    # Remove the signature to prepare hash computation
    data["signature"] = ""

    save_threat_model(filename, data)

    data = open_threat_model(filename)

    # Update with the new signature
    data["signature"] = hash_file(filename)

    save_threat_model(filename, data)


if __name__ == "__main__":
    for arg in sys.argv:
        if arg.endswith(".json"):
            print(f"Updating {arg}")
            update_threat_model_header(arg)
