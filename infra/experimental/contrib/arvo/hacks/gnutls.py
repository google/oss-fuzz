"""GnuTLS project-specific hacks."""

from . import ProjectHack


class GnuTLSHack(ProjectHack):
  """Hacks for the GnuTLS project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix GnuTLS Dockerfile issues."""
    dft.str_replace(" libnettle6 ", " ")
    dft.replace(r".*client_corpus_no_fuzzer_mode.*", "")
    dft.replace(r".*server_corpus_no_fuzzer_mode.*", "")
    return True
