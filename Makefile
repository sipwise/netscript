# for syntax checks
BASH_SCRIPTS = deployment.sh
NGCP_VERSION ?= $(shell git log --pretty=format:"%h" -1 deployment.sh)
NGCP_VERSION := $(strip $(NGCP_VERSION))

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
	echo "Adjust version information string in deployment.sh to ${NGCP_VERSION}"
	sed -i "s/SCRIPT_VERSION=\"%SCRIPT_VERSION%\"/SCRIPT_VERSION=${NGCP_VERSION}/" deployment.sh


.PHONY: clean install build syntaxcheck shellcheck script_version
# EOF
