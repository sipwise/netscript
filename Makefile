# for syntax checks
BASH_SCRIPTS = deployment.sh
VERSION=$(shell git log --pretty=format:"%h" -1 deployment.sh)

syntaxcheck: shellcheck

shellcheck:
	@echo -n "Checking for shell syntax errors"; \
	for SCRIPT in $(BASH_SCRIPTS); do \
		test -r $${SCRIPT} || continue ; \
		bash -n $${SCRIPT} || exit ; \
		echo -n "."; \
	done; \
	echo " done."; \

script_version:
	echo "Adjust version information string in deployment.sh to ${VERSION}"
	sed -i "s/SCRIPT_VERSION=\"%SCRIPT_VERSION%\"/SCRIPT_VERSION=${VERSION}/" deployment.sh

# EOF
