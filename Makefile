.PHONY: check theme sandbox runtime
check:
	python3 -m unittest discover -s tests -v
	python3 -m py_compile scripts/*.py tooling/*.py
	bash -n deploy/keycloak-entrypoint.sh deploy/postgres/init.sh
	node --check tooling/runtime.mjs
	node --check tooling/extended-runtime.mjs
	node --check tooling/policy-runtime.mjs
	node --check tooling/localization-runtime.mjs
	node --check tooling/receiver-audience-runtime.mjs
	node --check tooling/configuration-lookup-runtime.mjs
	node --input-type=module --check < themes/console-policy.js
	node --test tests/*.test.mjs
	git diff --check

theme:
	python3 tooling/build_theme.py

sandbox: theme
	python3 scripts/generate.py --mode sandbox

runtime:
	node tooling/runtime.mjs
