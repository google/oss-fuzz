"""Project-specific hacks for fixing Dockerfiles and build scripts.

This module contains project-specific fixes that solve building/compiling problems
for various OSS-Fuzz projects. Each project has its own module with dedicated
hack functions.
"""

import importlib

from abc import ABC, abstractmethod
from pathlib import Path

try:
  from ..arvo_utils import DockerfileModifier
except ImportError:
  # Fallback for when module is imported directly
  from arvo_utils import DockerfileModifier


class ProjectHack(ABC):
  """Base class for project-specific hacks."""

  def __init__(self):
    self.commit_date = None

  def set_commit_date(self, commit_date):
    """Set the commit date for hacks that need it."""
    self.commit_date = commit_date

  @abstractmethod
  def apply_dockerfile_fixes(self, dft: DockerfileModifier) -> bool:
    """Apply project-specific fixes to a Dockerfile.
        
        Args:
            dft: DockerfileModifier instance for the project's Dockerfile.
            
        Returns:
            True if fixes were applied successfully, False otherwise.
        """
    pass

  def apply_build_script_fixes(self, dft: DockerfileModifier) -> bool:
    """Apply project-specific fixes to a build script.
        
        Args:
            dft: DockerfileModifier instance for the project's build script.
            
        Returns:
            True if fixes were applied successfully, False otherwise.
        """
    # Default implementation - no build script fixes
    return True

  def apply_extra_fixes(self, source_dir: Path) -> bool:
    """Apply extra project-specific fixes that require file system operations.
        
        Args:
            source_dir: Path to the source directory.
            
        Returns:
            True if fixes were applied successfully, False otherwise.
        """
    # Default implementation - no extra fixes
    return True


def get_project_hack(project_name: str) -> ProjectHack | None:
  """Get a project hack instance by name using dynamic import."""
  try:
    # Try to import the module for this project
    module = importlib.import_module(f".{project_name}", __name__)

    # Look for a class that ends with 'Hack' and is a subclass of ProjectHack
    for attr_name in dir(module):
      attr = getattr(module, attr_name)
      if (isinstance(attr, type) and issubclass(attr, ProjectHack) and
          attr != ProjectHack):
        return attr()

    # If no hack class found, return None
    return None

  except ImportError:
    # No hack module for this project
    return None


# Helper functions that can be reused across projects
def x265_fix(dft: DockerfileModifier) -> None:
  """Apply x265-specific fixes to the dockerfile modifier.
    
    This is a common fix used by multiple projects that depend on x265.
    The order of these replacements matters.
    """
  dft.replace(
      r'RUN\shg\sclone\s.*bitbucket.org/multicoreware/x265\s*(x265)*',
      "RUN git clone "
      "https://bitbucket.org/multicoreware/x265_git.git x265\n")
  dft.replace(
      r'RUN\shg\sclone\s.*hg\.videolan\.org/x265\s*(x265)*', "RUN git clone "
      "https://bitbucket.org/multicoreware/x265_git.git x265\n")
