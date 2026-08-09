"""LibYang project-specific hacks."""

from . import ProjectHack


class LibYangHack(ProjectHack):
  """Hacks for the LibYang project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix LibYang Dockerfile issues."""
    dft.str_replace(
        'RUN git clone https://github.com/PCRE2Project/pcre2 pcre2 &&',
        "RUN git clone https://github.com/PCRE2Project/pcre2 pcre2\n"
        "RUN ")
    return True
