import json
from sys import platform
import subprocess
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

if platform == "linux" or platform == "linux2":
    # linux
    source = "Ubuntu"
elif platform == "darwin":
    # OS X
    source = "macOS"
elif platform == "win32":
    # Windows...
    source = "Windows"

with open('threatmodel-' + source + '.json', 'r') as json_file:
    model = json.load(json_file)

for metric in model['metrics']:

    print("Executing check for " + metric["name"] + " with elevation: " + metric["implementation"]["elevation"] + " and command: " + metric["implementation"]["target"])

    # Execute the CLI command using subprocess.run()
    if source == "Windows":
        result = subprocess.run(["powershell.exe", "-Command", metric["implementation"]["target"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    else:
        result = subprocess.run(metric["implementation"]["target"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Check for successful execution
    print(f"Return code: {result.returncode}")
    print(f"{Fore.GREEN}Stdout:\n{result.stdout}{Style.RESET_ALL}")
    print(f"{Fore.RED}Stderr:\n{result.stderr}{Style.RESET_ALL}")




