# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Build-script contract tests using real CMake, Ninja and C++ compilation.

Run on Linux with cmake, ninja, c++, zip, strip and /usr/bin/ccache installed.
These exercise target selection and errors, not ClickHouse instrumentation.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'),
                     'Linux build environment')
class BuildTest(unittest.TestCase):
  """Check the build script's public environment-to-artifact interface."""

  def setUp(self):
    for tool in ['cmake', 'ninja', 'cc', 'c++', 'zip', 'strip']:
      if not shutil.which(tool):
        self.skipTest(f'{tool} is required')
    if not Path('/usr/bin/ccache').is_file():
      self.skipTest('/usr/bin/ccache is required')
    self.directory = tempfile.TemporaryDirectory(
        prefix='clickhouse-build-test-')
    self.addCleanup(self.directory.cleanup)
    self.root = Path(self.directory.name)
    self.source = self.root / 'src' / 'ClickHouse'
    self.output = self.root / 'out'
    # Create all source directories expected by the build script.
    for relative in ['src', 'programs', 'contrib', 'tests/fuzz/dictionaries']:
      (self.source / relative).mkdir(parents=True)
    self.output.mkdir()
    cmake = [
        'cmake_minimum_required(VERSION 3.16)',
        'project(build_contract LANGUAGES CXX)',
    ]
    for target in ['b_fuzzer', 'c_fuzzer', 'd_fuzzer']:
      (self.source / 'src' /
       f'{target}.cpp').write_text('int main() { return 0; }\n')
      cmake.append(f'add_executable({target} src/{target}.cpp)')
    (self.source / 'CMakeLists.txt').write_text('\n'.join(cmake) + '\n')
    (self.source / 'tests/fuzz/all.dict').write_text('word="SELECT"\n')
    (self.source /
     'tests/fuzz/b_fuzzer.options').write_text('[libfuzzer]\ndict = all.dict\n')
    # Include the historical SQL directory too, so a comparison with the old
    # script reaches target-selection and missing-dictionary behavior.
    for directory in ['0_stateless', '1_stateful']:
      queries = self.source / 'tests/queries' / directory
      queries.mkdir(parents=True)
      (queries / 'seed.sql').write_text('SELECT 1;\n')
    self.environment = dict(os.environ)
    self.environment.pop('OSS_FUZZ_CI', None)
    # The builder forces Clang's ccache mode; fixtures use the system compiler.
    self.environment.pop('CCACHE_COMPILERTYPE', None)
    self.environment.update({
        'SRC': str(self.root / 'src'),
        'OUT': str(self.output),
        'WORK': str(self.root / 'work'),
        'CCACHE_DIR': str(self.root / 'ccache'),
        'CC': 'cc',
        'CXX': 'c++',
        'SANITIZER': 'address',
        'LIB_FUZZING_ENGINE': '-fsanitize=fuzzer',
    })

  def build(self):
    return subprocess.run(
        ['bash', '-eu',
         str(Path(__file__).with_name('build.sh'))],
        env=self.environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False)

  def executable_names(self):
    return sorted(path.name
                  for path in self.output.iterdir()
                  if path.is_file() and os.access(path, os.X_OK))

  def test_ci_builds_two_enabled_targets(self):
    self.environment['OSS_FUZZ_CI'] = '1'
    result = self.build()
    self.assertEqual(result.returncode, 0, result.stdout)
    self.assertEqual(self.executable_names(), ['b_fuzzer', 'c_fuzzer'])

  def test_ci_zero_builds_all_enabled_targets(self):
    self.environment['OSS_FUZZ_CI'] = '0'
    result = self.build()
    self.assertEqual(result.returncode, 0, result.stdout)
    self.assertEqual(self.executable_names(),
                     ['b_fuzzer', 'c_fuzzer', 'd_fuzzer'])

  def test_ci_replaces_outputs_from_previous_daily_build(self):
    daily = self.build()
    self.assertEqual(daily.returncode, 0, daily.stdout)
    self.assertEqual(self.executable_names(),
                     ['b_fuzzer', 'c_fuzzer', 'd_fuzzer'])

    self.environment['OSS_FUZZ_CI'] = '1'
    ci = self.build()
    self.assertEqual(ci.returncode, 0, ci.stdout)
    self.assertEqual(self.executable_names(), ['b_fuzzer', 'c_fuzzer'])

  def test_daily_build_includes_all_enabled_targets(self):
    # Source presence is not sufficient: optional dependencies may disable it.
    (self.source /
     'src/a_optional_fuzzer.cpp').write_text('int main() { return 0; }\n')
    result = self.build()
    self.assertEqual(result.returncode, 0, result.stdout)
    self.assertEqual(self.executable_names(),
                     ['b_fuzzer', 'c_fuzzer', 'd_fuzzer'])

  def test_coverage_stages_mapped_sources_and_headers(self):
    for tool in ['clang', 'clang++', 'llvm-cov']:
      if not shutil.which(tool):
        self.skipTest(f'{tool} is required')

    self.environment.update({
        'CC': 'clang',
        'CXX': 'clang++',
        'SANITIZER': 'coverage',
    })
    (self.source / 'src/mapped_header.h'
    ).write_text('inline int mapped_value() { return 1; }\n')
    (self.source / 'src/b_fuzzer.cpp').write_text(
        '#include "mapped_header.h"\n'
        'int main() { return mapped_value(); }\n')
    with (self.source / 'CMakeLists.txt').open('a') as cmake:
      for target in ['b_fuzzer', 'c_fuzzer', 'd_fuzzer']:
        cmake.write(
            f'target_compile_options({target} PRIVATE '
            '-fprofile-instr-generate -fcoverage-mapping '
            '"-ffile-prefix-map=${CMAKE_SOURCE_DIR}=${CMAKE_BINARY_DIR}")\n'
            f'target_link_options({target} PRIVATE '
            '-fprofile-instr-generate -fcoverage-mapping)\n')

    result = self.build()
    self.assertEqual(result.returncode, 0, result.stdout)

    mapped_root = Path(self.environment['WORK']) / 'clickhouse'
    self.assertEqual((mapped_root / 'src/b_fuzzer.cpp').read_text(),
                     '#include "mapped_header.h"\n'
                     'int main() { return mapped_value(); }\n')
    self.assertEqual((mapped_root / 'src/mapped_header.h').read_text(),
                     'inline int mapped_value() { return 1; }\n')

    (self.source / 'src/mapped_header.h'
    ).write_text('inline int mapped_value() { return 2; }\n')
    rebuilt = self.build()
    self.assertEqual(rebuilt.returncode, 0, rebuilt.stdout)
    self.assertEqual((mapped_root / 'src/mapped_header.h').read_text(),
                     'inline int mapped_value() { return 2; }\n')

  def test_missing_dictionary_rejects_unusable_build(self):
    (self.source / 'tests/fuzz/b_fuzzer.options'
    ).write_text('[libfuzzer]\ndict = missing.dict\n')
    result = self.build()
    self.assertNotEqual(result.returncode, 0, result.stdout)
    (self.source /
     'tests/fuzz/dictionaries/missing.dict').write_text('word="SELECT"\n')
    repaired = self.build()
    self.assertEqual(repaired.returncode, 0, repaired.stdout)

  def test_preserves_project_compiler_policy(self):
    (self.source / 'cmake').mkdir()
    (self.source / 'cmake/warnings.cmake'
    ).write_text('add_compile_options(-Wno-deprecated-declarations)\n')
    cmake = [
        'cmake_minimum_required(VERSION 3.16)',
        'project(build_contract LANGUAGES CXX)',
        'add_compile_options(-Werror)',
        'include(cmake/warnings.cmake)',
    ]
    for target in ['b_fuzzer', 'c_fuzzer', 'd_fuzzer']:
      cmake.append(f'add_executable({target} src/{target}.cpp)')
    (self.source / 'CMakeLists.txt').write_text('\n'.join(cmake) + '\n')
    (self.source / 'src/b_fuzzer.cpp').write_text(
        '[[deprecated]] int legacy_api() { return 0; }\n'
        'int main() { return legacy_api(); }\n')
    result = self.build()
    self.assertEqual(result.returncode, 0, result.stdout)
    self.assertEqual(self.executable_names(),
                     ['b_fuzzer', 'c_fuzzer', 'd_fuzzer'])


if __name__ == '__main__':
  unittest.main()
