.PHONY: tests

update:
	python3 src/publish/update-models.py threatmodel-macOS.json threatmodel-Windows.json

validate:
	python3 src/publish/validate-models.py threatmodel-*.json

vulns:
	python3 src/cve/build-port-vulns-db.py
	python3 src/cve/build-vendor-vulns-db.py

tests:
	./tests/run-tests.sh

import:
	python3 src/cli/import.py threatmodel-macOS.json
	python3 src/cli/import.py threatmodel-Windows.json
	python3 src/cli/import.py threatmodel-Linux.json
