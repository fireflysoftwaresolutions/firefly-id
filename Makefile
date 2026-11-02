.PHONY: check theme sandbox runtime docs
check:
	python3 -m unittest discover -s tests -v
	python3 -m py_compile scripts/*.py tooling/*.py
	bash -n deploy/keycloak-entrypoint.sh deploy/postgres/init.sh
	node --check tooling/runtime.mjs
	node --check tooling/identity-artwork.mjs
	node --check tooling/extended-runtime.mjs
	node --check tooling/policy-runtime.mjs
	node --check tooling/localization-runtime.mjs
	node --check tooling/receiver-audience-runtime.mjs
	node --check tooling/configuration-lookup-runtime.mjs
	node --check tooling/native-runtime.mjs
	node --check tooling/privileged-runtime.mjs
	node --check tooling/master-transition-runtime.mjs
	node --check tooling/master-action-links.mjs
	node --check tooling/reproofing-runtime.mjs
	node --check tooling/documentation-runtime.mjs
	node --check tooling/documentation-diagrams.mjs
	node --check themes/firefly-id-native/account/resources/js/native-account-links.js
	node --check themes/firefly-id/login/resources/js/native-ui.js
	node --input-type=module --check < themes/console-policy.js
	node --test tests/*.test.mjs
	git diff --check

theme:
	python3 tooling/build_theme.py

sandbox: theme
	python3 scripts/generate.py --mode sandbox

runtime:
	node tooling/runtime.mjs

docs:
	node tooling/documentation-diagrams.mjs
	python3 -m mkdocs build --strict
