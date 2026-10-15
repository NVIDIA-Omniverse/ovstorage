# Makefile for the combined ovstorage Sphinx documentation.
#
# The Sphinx source directory is the repository root so that the component guides
# are published from ovstorage/docs/public/ and ovstorage-usd-resolver/docs/.
# conf.py in this directory selects which files become pages.

SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
BUILDDIR      = _build

DOCS_DIR      = $(abspath .)
PROJECT_ROOT  = $(abspath ..)

UV            ?= uv
UVRUN         = $(UV) run --no-project --python '>=3.11' --with-requirements "$(DOCS_DIR)/requirements.txt"

help:
	@$(UVRUN) $(SPHINXBUILD) -M help "$(PROJECT_ROOT)" "$(DOCS_DIR)/$(BUILDDIR)" -c "$(DOCS_DIR)" $(SPHINXOPTS) $(O)

.PHONY: help clean html linkcheck

clean:
	@rm -rf $(BUILDDIR)

html:
	$(UVRUN) $(SPHINXBUILD) -M html "$(PROJECT_ROOT)" "$(DOCS_DIR)/$(BUILDDIR)" -c "$(DOCS_DIR)" $(SPHINXOPTS) $(O)

linkcheck:
	$(UVRUN) $(SPHINXBUILD) -M linkcheck "$(PROJECT_ROOT)" "$(DOCS_DIR)/$(BUILDDIR)" -c "$(DOCS_DIR)" $(SPHINXOPTS) $(O)
