"""LibreOffice project-specific hacks."""

from . import ProjectHack


class LibreOfficeHack(ProjectHack):
  """Hacks for the LibreOffice project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix LibreOffice Dockerfile issues."""
    # Fix setup script and disable various commands
    dft.str_replace(
        'RUN ./bin/oss-fuzz-setup.sh',
        "RUN sed -i 's|svn export --force -q https://github.com|"
        "#svn export --force -q https://github.com|g' "
        "./bin/oss-fuzz-setup.sh")
    dft.str_replace('RUN svn export', '# RUN svn export')
    dft.str_replace('ADD ', '# ADD ')
    dft.str_replace('RUN zip', '# RUN zip')
    dft.str_replace('RUN mkdir afl-testcases', "# RUN mkdir afl-testcases")
    dft.str_replace(
        'RUN ./bin/oss-fuzz-setup.sh',
        "# RUN ./bin/oss-fuzz-setup.sh")  # Avoid downloading not related stuff
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix LibreOffice build script issues."""
    # If you don't want to destroy your life.
    # Please leave this project alone. too hard to fix and the compiling
    # takes several hours
    line = '$SRC/libreoffice/bin/oss-fuzz-build.sh'
    dft.insert_line_before(
        line, "sed -i 's/make fuzzers/make fuzzers -i/g' "
        "$SRC/libreoffice/bin/oss-fuzz-build.sh")
    dft.insert_line_before(
        line, "sed -n -i '/#starting corpuses/q;p' "
        "$SRC/libreoffice/bin/oss-fuzz-build.sh")
    dft.insert_line_before(
        line, r"sed -n -i '/pushd instdir\/program/q;p' "
        r"$SRC/libreoffice/bin/oss-fuzz-build.sh")
    dft.insert_line_before(
        line, 'echo "pushd instdir/program && mv *fuzzer $OUT" >> '
        '$SRC/libreoffice/bin/oss-fuzz-build.sh')
    return True
