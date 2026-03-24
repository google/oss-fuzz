"""YARA project-specific hacks."""

from . import ProjectHack


class YARAHack(ProjectHack):
  """Hacks for the YARA project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix YARA Dockerfile issues."""
    if 'bison' not in dft.content:
      dft.insert_line_before(
          "RUN git clone https://github.com/VirusTotal/yara.git",
          "RUN apt install -y bison")
    return True
