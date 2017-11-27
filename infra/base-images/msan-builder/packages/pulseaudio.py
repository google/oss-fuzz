from __future__ import print_function
import glob
import os
import subprocess

import package


class Package(package.Package):
  """PulseAudio package."""

  def __init__(self):
    super(Package, self).__init__('pulseaudio')

  def PostDownload(self, source_directory):
    """Remove blacklisted patches."""
    # Fix *droid* patches.
    bad_patch_path = os.path.join(
        source_directory, 'debian', 'patches',
        '0600-droid-sync-with-upstream-for-Android-5-support-and-b.patch')
    if not os.path.exists(bad_patch_path):
      return

    print('Applying custom patches.')
    package.ApplyPatch(source_directory, 'pulseaudio_fix_android.patch')
