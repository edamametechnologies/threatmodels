'''Update threat models hash and dates'''

import sys
import hashlib
import json
import datetime


def hash_file(filename):
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


def update_json_file(filename):
    # Open the file in read mode and load the JSON
    with open(filename, 'r') as file:
        data = json.load(file)

    # Update the date and hash
    data["date"] = datetime.datetime.now().strftime("%B %dth %Y")
    data["signature"] = hash_file(filename)

    # Open the file in write mode and save the updated JSON
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)


for arg in sys.argv:
    if arg.endswith(".json"):
        print(f"updating {arg}")
        update_json_file(arg)
