"""ARVO data management module.

This module provides data management functions for ARVO reproducer,
including configuration mappings and Docker/build script fixes.
"""

from pathlib import Path
from typing import Any, Dict, Tuple
from datetime import datetime
from hacks import get_project_hack

from arvo_utils import (DockerfileModifier, CHANGED_KEY, CHANGED_TYPE,
                        GLOBAL_STR_REPLACE, UPDATE_TABLE)


def update_resource_info(item_name: str, item_url: str,
                         item_type: str) -> Tuple[str, str, str]:
  """Update resource information based on configuration tables.
    
    Args:
        item_name: Name of the resource item.
        item_url: URL of the resource.
        item_type: Type of the resource.
        
    Returns:
        Tuple of (updated_name, updated_url, updated_type).
    """
  if item_name in CHANGED_KEY:
    item_name = CHANGED_KEY[item_name]

  if item_name in UPDATE_TABLE:
    resource_type = CHANGED_TYPE.get(item_name, 'git')
    return item_name, UPDATE_TABLE[item_name], resource_type
  else:
    return item_name, item_url, item_type


def dockerfile_cleaner(dockerfile_path: str | Path) -> None:
  """Clean dockerfile by removing git branch-specific arguments.
    
    Args:
        dockerfile_path: Path to the Dockerfile to clean.
    """
  dft = DockerfileModifier(dockerfile_path)
  dft.replace(r'(--single-branch\s+)', "")  # --single-branch
  dft.replace(r'(--branch\s+\S+\s+|-b\s\S+\s+|--branch=\S+\s+)',
              "")  # remove --branch or -b
  dft.flush()


def fix_dockerfile(dockerfile_path: str | Path,
                   project: str | None = None,
                   commit_date: datetime | None = None) -> bool:
  """Fix the dockerfile for specific projects and general issues.
    
    Args:
        dockerfile_path: Path to the Dockerfile to fix.
        project: Name of the project for project-specific fixes.
        commit_date: Target commit date (required for some projects like GDAL).
        
    Returns:
        True if fixes were applied successfully, False otherwise.
    """

  dockerfile_cleaner(dockerfile_path)
  dft = DockerfileModifier(dockerfile_path)

  # Some dockerfile forgets to apt update before apt install
  # and we have to install/set ca-certificate/git sslVerify to avoid
  # certificates issues
  # TODO: improve regex
  dft.replace_once(
      r'RUN apt', "RUN apt update -y && apt install git ca-certificates -y && "
      "git config --global http.sslVerify false && "
      "git config --global --add safe.directory '*'\nRUN apt")
  dft.str_replace_all(GLOBAL_STR_REPLACE)

  # Apply project-specific hacks that solve building/compiling problems
  if project:
    hack = get_project_hack(project)
    if hack:
      # Pass commit_date to the hack if it needs it
      if hasattr(hack, 'set_commit_date') and commit_date:
        hack.set_commit_date(commit_date)
      if not hack.apply_dockerfile_fixes(dft):
        return False

  dft.clean_comments()
  return dft.flush()


def fix_build_script(file_path: Path, project_name: str) -> bool:
  """Fix the build script for specific projects.
    
    Args:
        file_path: Path to the build script file.
        project_name: Name of the project.
        
    Returns:
        True if fixes were applied successfully, False otherwise.
    """
  if not file_path.exists():
    return True

  dft = DockerfileModifier(file_path)

  # Apply project-specific build script hacks
  hack = get_project_hack(project_name)
  if hack and not hack.apply_build_script_fixes(dft):
    return False

  return dft.flush()


def extra_scripts(project_name: str, source_dir: Path) -> bool:
  """Execute extra scripts for specific projects.
    
    This function allows us to modify build.sh scripts and other stuff
    to modify the compiling setting.
    
    Args:
        project_name: Name of the project.
        source_dir: Path to the source directory.
        
    Returns:
        True if scripts executed successfully, False otherwise.
    """
  # Apply project-specific extra fixes
  hack = get_project_hack(project_name)
  if hack and not hack.apply_extra_fixes(source_dir):
    return False
  return True


def special_component(project_name: str, item_key: str, item: Dict[str, Any],
                      dockerfile: str | Path) -> bool:
  """Check if a component requires special handling.
    
    TODO: Theoretically, we can remove this func since other parts gonna
    handle the submodule, but not tested.
    These components are submodules, but their info are in srcmap.
    
    Args:
        project_name: Name of the project.
        item_key: Key of the item in srcmap.
        item: Item data from srcmap.
        dockerfile: Path to the dockerfile.
        
    Returns:
        True if component should be skipped, False otherwise.
    """
  # These components are submodules, but their info are in srcmap
  if project_name == 'libressl' and item_key == '/src/libressl/openbsd':
    return False

  if project_name == 'gnutls' and item_key == '/src/gnutls/nettle':
    # Just Ignore since we have submodule update --init
    with open(dockerfile, encoding='utf-8') as f:
      dt = f.read()
    if item['rev'] not in dt:
      return True
    else:
      return False

  return False


def skip_component(project_name: str, item_name: str) -> bool:
  """Check if a component should be skipped during processing.
    
    TODO: solve the submodule problem in a decent way
    
    Args:
        project_name: Name of the project.
        item_name: Name of the item/component.
        
    Returns:
        True if component should be skipped, False otherwise.
    """
  NO_OPERATION = (
      "/src",
      "/src/LPM/external.protobuf/src/external.protobuf",
      "/src/libprotobuf-mutator/build/external.protobuf/src/external.protobuf",
  )
  item_name = item_name.strip(" ")

  # Special for skia, Skip since they are done by submodule init
  if project_name in ['skia', 'skia-ftz']:
    if item_name.startswith("/src/skia/"):
      return True

  if item_name in NO_OPERATION:
    return True

  return False


if __name__ == "__main__":
  pass
