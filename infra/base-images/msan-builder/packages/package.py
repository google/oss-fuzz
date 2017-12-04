import os
import subprocess

import apt

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


def ApplyPatch(source_directory, patch_name):
  """Apply custom patch."""
  subprocess.check_call(['patch', '-p1', '-i',
                         os.path.join(SCRIPT_DIR, patch_name)],
                        cwd=source_directory)


class PackageException(Exception):
  """Base package exception."""


class Package(object):
  """Base package."""

  def __init__(self, name):
    self.name = name

  def PreBuild(self, source_directory, env):
    return

  def PostBuild(self, source_directory, env):
    return

  def PreDownload(self, download_directory):
    return

  def PostDownload(self, source_directory):
    return

  def InstallBuildDeps(self):
    """Install build dependencies for a package."""
    subprocess.check_call(['apt-get', 'build-dep', '-y', self.name])

  def DownloadSource(self, download_directory):
    """Download the source for a package."""
    self.PreDownload(download_directory)

    apt_cache = apt.Cache()
    source_directory = apt_cache[self.name].versions[0].fetch_source(
        download_directory)

    self.PostDownload(source_directory)
    return source_directory

  def Build(self, source_directory, env):
    """Build .deb packages."""
    self.PreBuild(source_directory, env)
    subprocess.check_call(
        ['dpkg-buildpackage', '-us', '-uc', '-b'],
        cwd=source_directory, env=env)
    self.PostBuild(source_directory, env)


