#!/bin/sh

if command -v mokutil >/dev/null 2>&1; then
    LANG=C mokutil --sb-state | grep -q 'SecureBoot enabled' || echo secure_boot_disabled
else
    # If mokutil is missing, we can't verify, but assuming disabled if we can't check might be safe or noisy.
    # For now, only report if we can check and it says disabled.
    # Or echo "unknown" ?
    # Existing script echoed "secure_boot_disabled" if mokutil failed or grep failed.
    # I'll stick to that behavior but clean up the garbage line.
    LANG=C mokutil --sb-state 2>/dev/null | grep -q 'SecureBoot enabled' || echo secure_boot_disabled
fi
