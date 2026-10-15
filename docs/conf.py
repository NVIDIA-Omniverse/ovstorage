# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sphinx configuration for the combined ovstorage documentation site.
#
# The source directory is the repository root, not this directory, so the
# component guides under ovstorage/docs/public/ and ovstorage-usd-resolver/docs/
# are published from their own locations and their relative Markdown links keep
# working. See README.md in this directory for how to build.

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath("_ext"))

REPO_ROOT = Path(__file__).resolve().parent.parent

# -- Project information -----------------------------------------------------
project = "ovstorage"
copyright = "2026, NVIDIA Corporation"
author = "NVIDIA Corporation"


def _snapshot_label() -> str:
    version_md = REPO_ROOT / "VERSION.md"
    if version_md.is_file():
        match = re.search(r"(?:Review|Release) label: `([^`]+)`", version_md.read_text(encoding="utf-8"))
        if match:
            return match[1]
    return "preview"


version = release = _snapshot_label()

# -- General configuration ---------------------------------------------------
extensions = [
    "myst_parser",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinxcontrib.mermaid",
    "github_links",
]

root_doc = "docs/index"
source_suffix = {".md": "markdown"}

include_patterns = [
    "docs/*.md",
    "ovstorage/docs/public/**",
    "ovstorage-usd-resolver/docs/**",
]
# README.md here is the GitHub-browsable index that index.md replaces on the site,
# documentation-site.md is contributor-facing build instructions, and AGENTS.md
# files are agent routing notes; none is published documentation.
exclude_patterns = [
    "docs/README.md",
    "docs/documentation-site.md",
    "docs/_build",
    "**/AGENTS.md",
    "**/.*",
]

templates_path = ["_templates"]

# -- Options for MyST (Markdown) ---------------------------------------------
myst_enable_extensions = ["colon_fence", "deflist", "strikethrough", "tasklist"]
myst_heading_anchors = 4
# ```mermaid fences render on GitHub as-is; on the site they become diagrams.
myst_fence_as_directive = ["mermaid"]

# -- Options for github_links (links to files outside the docs site) ---------
# Builds of an unpublished snapshot point these at the repository and branch
# that hold it, so file links resolve before the public repository has them.
github_links_base = os.environ.get("DOCS_GITHUB_URL", "https://github.com/NVIDIA-Omniverse/ovstorage")
github_links_branch = os.environ.get("DOCS_GITHUB_REF", "main")

# -- Options for HTML output -------------------------------------------------
html_theme = "nvidia_sphinx_theme"
html_title = "ovstorage"

html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 4,
    "pygments_light_style": "sas",
    "pygments_dark_style": "github-dark",
    "icon_links": [
        {
            "name": "GitHub",
            "url": github_links_base,
            "icon": "fa-brands fa-github",
            "type": "fontawesome",
        },
    ],
}

html_static_path = ["_static"]
html_css_files = ["css/custom.css"]
