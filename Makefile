validate:
	python3 src/publish/validate-models.py threatmodel-*.json

vulns:
	python3 src/cve/build-port-vulns-db.py
	python3 src/cve/build-vendor-vulns-db.py

