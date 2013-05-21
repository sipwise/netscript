# for syntax checks
BASH_SCRIPTS = deployment.sh

syntaxcheck: shellcheck

shellcheck:
	@echo -n "Checking for shell syntax errors"; \
	for SCRIPT in $(BASH_SCRIPTS); do \
		test -r $${SCRIPT} || continue ; \
		bash -n $${SCRIPT} || exit ; \
		echo -n "."; \
	done; \
	echo " done."; \

# EOF
