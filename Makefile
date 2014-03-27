# Makefile to test and clean.

all:
	@echo "Targets:  test, clean"

test:
	python -m unittest smbfs.tests

clean:
	find . \( -name "*~" -o -name "*.pyc" \) -delete
	rm -rf build dist smbfs.egg-info
