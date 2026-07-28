.PHONY: help validate test scan doctor

PYTHON ?= python3
SECWEAVER := PYTHONPATH=src $(PYTHON) -m secweaver

help:
	@$(SECWEAVER) --help

validate:
	@$(SECWEAVER) --config secweaver.toml validate

test:
	@PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

scan:
	@$(SECWEAVER) --config secweaver.toml scan

doctor:
	@$(SECWEAVER) --config secweaver.toml doctor
