# Makefile to test and clean.

all:
	@echo "Targets:  test, clean"

test:
	python -m unittest smbfs.tests.test_smbfs

clean:
	find . \( -name "*~" -o -name "*.pyc" \) -delete
