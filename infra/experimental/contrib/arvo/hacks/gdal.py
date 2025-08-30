"""GDAL project-specific hacks."""

from . import ProjectHack, register_hack


class GDALHack(ProjectHack):
  """Hacks for the GDAL project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix GDAL Dockerfile issues."""
    if not self.commit_date:
      # GDAL hacks require commit_date to work properly
      return False

    dft.append_line(f'ARG ARVO_TS="{self.commit_date.isoformat()}"')

    # Remove all --depth and checkout the cloned repo in build.sh
    build_clone_fix = r'''RUN awk -v ts="$ARVO_TS" '\
    /git clone/ { \
        gsub(/--depth[= ][0-9]+/, "", $0); \
        if (NF == 3) dir = $3; \
        else { \
            repo = $NF; \
            gsub(/.*\//, "", repo); \
            gsub(/\.git$/, "", repo); \
            dir = repo; \
        } \
        print $0 " && (pushd " dir " && commit=$(git log --before=\"" ts "\" --format=\"%H\" -n1) && git reset --hard $commit || exit 99 && popd) && (pushd " dir " && git submodule init && git submodule update --force && popd)"; \
        next \
    } \
    { print }' $SRC/build.sh > $SRC/build.sh.tmp && mv $SRC/build.sh.tmp $SRC/build.sh
    '''
    dft.append_line(build_clone_fix)

    # Fix GNUmakefile
    line = '''RUN [ -f /src/gdal/gdal/GNUmakefile ] && sed -i 's|(cd frmts; $(MAKE))|(cd frmts; $(MAKE) clean; $(MAKE))|' /src/gdal/gdal/GNUmakefile || true'''
    dft.append_line(line)

    # Fix build script path
    dft.append_line(
        '''RUN sed -i 's|BUILD_SH_FROM_REPO="$SRC/gdal/fuzzers/build.sh"|BUILD_SH_FROM_REPO=$0|g' $SRC/build.sh'''
    )

    return True


# Register the hack
register_hack("gdal", GDALHack)
