# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolve Markdown links to repository files that are not documentation pages.

Component guides link to examples, tools, agent routing notes, and other source
files. Those files are not pages on the site, so each such link becomes a link
to the file on GitHub. The extension also writes a root ``index.html`` that
redirects to the landing page, because the landing page lives at
``docs/index.html``.
"""

from __future__ import annotations

import posixpath
from pathlib import Path

from docutils import nodes
from sphinx import addnodes
from sphinx.application import Sphinx
from sphinx.transforms.post_transforms import SphinxPostTransform


class GitHubFileLinks(SphinxPostTransform):
    """Rewrite MyST links to non-page repository files before MyST resolves them."""

    # MyST's reference resolver runs at priority 9; this must run first.
    default_priority = 8

    def run(self, **kwargs) -> None:
        srcdir = Path(self.app.srcdir)
        for node in list(self.document.findall(addnodes.pending_xref)):
            if node.get("reftype") != "myst":
                continue
            relative, fragment = self._repository_path(node, srcdir)
            if relative is None:
                continue
            kind = "tree" if (srcdir / relative).is_dir() else "blob"
            config = self.app.config
            url = f"{config.github_links_base}/{kind}/{config.github_links_branch}/{relative}"
            if fragment:
                url += f"#{fragment}"
            reference = nodes.reference("", "", internal=False, refuri=url)
            reference.extend(node[0].deepcopy().children if node.children else [])
            if not reference.children:
                reference.append(nodes.literal(relative, relative))
            node.replace_self(reference)

    def _repository_path(self, node, srcdir: Path) -> tuple[str | None, str]:
        target = node.get("reftarget", "")
        if node.get("refdomain") == "doc":
            if target in self.env.all_docs:
                return None, ""
            candidate = f"{target}.md"
            fragment = node.get("reftargetid") or ""
        else:
            if not target or "://" in target or target.startswith("#"):
                return None, ""
            path, _, fragment = target.partition("#")
            docdir = posixpath.dirname(node.get("refdoc", self.env.docname))
            candidate = posixpath.normpath(posixpath.join(docdir, path))
        if candidate.startswith("..") or not (srcdir / candidate).exists():
            return None, ""
        return candidate, fragment


def _write_root_redirect(app: Sphinx, exception) -> None:
    if exception or app.builder.format != "html" or app.config.root_doc == "index":
        return
    index = Path(app.outdir) / "index.html"
    if index.exists():
        return
    landing = app.builder.get_target_uri(app.config.root_doc)
    index.write_text(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">"
        f"<meta http-equiv=\"refresh\" content=\"0; url={landing}\">"
        f"<link rel=\"canonical\" href=\"{landing}\"><title>ovstorage</title></head>"
        f"<body><a href=\"{landing}\">ovstorage documentation</a></body></html>\n",
        encoding="utf-8",
    )


def setup(app: Sphinx) -> dict:
    app.add_config_value("github_links_base", "", "env")
    app.add_config_value("github_links_branch", "main", "env")
    app.add_post_transform(GitHubFileLinks)
    app.connect("build-finished", _write_root_redirect)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
