from model import Model
import logging
import os
import sys
import getpass
import subprocess
from pathlib import Path

logging.basicConfig(
        format='[%(asctime)s][%(levelname)s] %(message)s',
        )

OK_LEVEL = 10
logging.addLevelName(OK_LEVEL, "\033[32mOK\033[0m")


def ok(self, message, *args, **kwargs):
    if self.isEnabledFor(OK_LEVEL):
        self._log(OK_LEVEL, message, args, **kwargs)


logging.Logger.ok = ok
logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

username = os.environ.get("EDAMAME_TEST_USERNAME") or getpass.getuser()


def test_env_vars_with_elevation(platform, username):
    """
    Test that environment variables are properly passed when running with admin elevation.
    This validates the runner_cli implementation.
    """
    logger.info(f"Running environment variable test for {platform}")
    
    # Use path relative to current working directory (which should be threatmodels root in CI)
    binary_name = "run_cli_test.exe" if platform == "Windows" else "run_cli_test"
    binary_path = Path("src/test/target/release") / binary_name
    
    if not binary_path.exists():
        logger.error(f"Rust test binary not found at: {binary_path.absolute()}")
        logger.error(f"Current working directory: {Path.cwd()}")
        logger.error("Build it first with: cargo build --release")
        return False
    
    # Convert to absolute path for execution
    binary_path = binary_path.absolute()
    logger.info(f"Using Rust binary at: {binary_path}")
    
    if platform == "macOS" or platform == "Linux":
        # Test script for Unix - simple one-liner to avoid arg parsing issues
        test_script = "test -n \"$HOME\" && test -d \"$HOME\" && test -n \"$USER\" && test -n \"$LOGNAME\""
        args = ["sudo", str(binary_path), test_script, username, "true", "10"]
        
    elif platform == "Windows":
        # Test script for Windows
        test_script = """
if (-not $env:USERPROFILE) { Write-Output "ERROR: USERPROFILE not set"; exit 1 }
if (-not (Test-Path $env:USERPROFILE)) { Write-Output "ERROR: USERPROFILE does not exist: $env:USERPROFILE"; exit 1 }
if (-not $env:HOME) { Write-Output "ERROR: HOME not set"; exit 1 }
if ($env:HOME -ne $env:USERPROFILE) { Write-Output "ERROR: HOME != USERPROFILE"; exit 1 }
if (-not $env:APPDATA) { Write-Output "ERROR: APPDATA not set"; exit 1 }
if (-not $env:LOCALAPPDATA) { Write-Output "ERROR: LOCALAPPDATA not set"; exit 1 }
exit 0
"""
        args = [str(binary_path), test_script, username, "true", "10"]
    else:
        logger.warning(f"Skipping env var test for unsupported platform: {platform}")
        return True
    
    try:
        logger.info(f"Running command: {' '.join(args[:2])} <script> ...")
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        
        if result.returncode == 0:
            logger.ok(f"Environment variables test passed for {platform}")
            return True
        else:
            logger.error(f"Environment variables test failed for {platform}")
            logger.error(f"Return code: {result.returncode}")
            logger.error(f"stdout: {result.stdout}")
            logger.error(f"stderr: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to run environment variables test: {e}")
        return False


# Run environment variable test before threat model tests
if not test_env_vars_with_elevation(Model(logger, ".", './src/test/ignore-tests.yaml', username).source, username):
    logger.error("Environment variable test failed. Threat model tests may not run correctly.")
    sys.exit(1)

model = Model(
    logger,
    dir_path=".",
    ignore_tests_path='./src/test/ignore-tests.yaml',
    username=username,
)

# If implementation_only is passed to the script, only implementation tests are run
implementation_only = len(sys.argv) > 1 and sys.argv[1] == "implementation_only"
results = model.run_metrics_sequentially(implementation_only)

print(results)

if results["error_count"] > 0:
    exit(1)
else:
    exit(0)
