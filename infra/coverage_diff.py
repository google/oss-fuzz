import os
import helper

OSS_FUZZ_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = os.path.join(OSS_FUZZ_DIR, 'build')

# TODO(rjotwani): Write usage
def usage():
    return

def main():
  """Get subcommand from program arguments and do it."""
  os.chdir(OSS_FUZZ_DIR)
  if not os.path.exists(BUILD_DIR):
    os.mkdir(BUILD_DIR)

  parser = argparse.ArgumentParser('coverage_diff.py', description='oss-fuzz helpers')
  subparsers = parser.add_subparsers(dest='command')



  generate_parser = subparsers.add_parser(
      'generate', help='Generate files for new project.')
  generate_parser.add_argument('project_name')

  build_image_parser = subparsers.add_parser('build_image',
                                             help='Build an image.')
  build_image_parser.add_argument('project_name')
  build_image_parser.add_argument('--pull',
                                  action='store_true',
                                  help='Pull latest base image.')
  build_image_parser.add_argument('--no-pull',
                                  action='store_true',
                                  help='Do not pull latest base image.')

  build_fuzzers_parser = subparsers.add_parser(
      'build_fuzzers', help='Build fuzzers for a project.')
  _add_architecture_args(build_fuzzers_parser)
  _add_engine_args(build_fuzzers_parser)
  _add_sanitizer_args(build_fuzzers_parser)
  _add_environment_args(build_fuzzers_parser)
  build_fuzzers_parser.add_argument('project_name')
  build_fuzzers_parser.add_argument('source_path',
                                    help='path of local source',
                                    nargs='?')
  build_fuzzers_parser.add_argument('--clean',
                                    dest='clean',
                                    action='store_true',
                                    help='clean existing artifacts.')
  build_fuzzers_parser.add_argument('--no-clean',
                                    dest='clean',
                                    action='store_false',
                                    help='do not clean existing artifacts '
                                    '(default).')
  build_fuzzers_parser.set_defaults(clean=False)

  check_build_parser = subparsers.add_parser(
      'check_build', help='Checks that fuzzers execute without errors.')
  _add_architecture_args(check_build_parser)
  _add_engine_args(check_build_parser,
                   choices=['libfuzzer', 'afl', 'honggfuzz', 'dataflow'])
  _add_sanitizer_args(check_build_parser,
                      choices=['address', 'memory', 'undefined', 'dataflow'])
  _add_environment_args(check_build_parser)
  check_build_parser.add_argument('project_name', help='name of the project')
  check_build_parser.add_argument('fuzzer_name',
                                  help='name of the fuzzer',
                                  nargs='?')

  run_fuzzer_parser = subparsers.add_parser(
      'run_fuzzer', help='Run a fuzzer in the emulated fuzzing environment.')
  _add_engine_args(run_fuzzer_parser)
  _add_sanitizer_args(run_fuzzer_parser)
  _add_environment_args(run_fuzzer_parser)
  run_fuzzer_parser.add_argument(
      '--corpus-dir', help='directory to store corpus for the fuzz target')
  run_fuzzer_parser.add_argument('project_name', help='name of the project')
  run_fuzzer_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  run_fuzzer_parser.add_argument('fuzzer_args',
                                 help='arguments to pass to the fuzzer',
                                 nargs=argparse.REMAINDER)

  coverage_parser = subparsers.add_parser(
      'coverage', help='Generate code coverage report for the project.')
  coverage_parser.add_argument('--no-corpus-download',
                               action='store_true',
                               help='do not download corpus backup from '
                               'OSS-Fuzz; use corpus located in '
                               'build/corpus/<project>/<fuzz_target>/')
  coverage_parser.add_argument('--port',
                               default='8008',
                               help='specify port for'
                               ' a local HTTP server rendering coverage report')
  coverage_parser.add_argument('--fuzz-target',
                               help='specify name of a fuzz '
                               'target to be run for generating coverage '
                               'report')
  coverage_parser.add_argument('--corpus-dir',
                               help='specify location of corpus'
                               ' to be used (requires --fuzz-target argument)')
  coverage_parser.add_argument('project_name', help='name of the project')
  coverage_parser.add_argument('extra_args',
                               help='additional arguments to '
                               'pass to llvm-cov utility.',
                               nargs='*')

  download_corpora_parser = subparsers.add_parser(
      'download_corpora', help='Download all corpora for a project.')
  download_corpora_parser.add_argument('--fuzz-target',
                                       help='specify name of a fuzz target')
  download_corpora_parser.add_argument('project_name',
                                       help='name of the project')

  reproduce_parser = subparsers.add_parser('reproduce',
                                           help='Reproduce a crash.')
  reproduce_parser.add_argument('--valgrind',
                                action='store_true',
                                help='run with valgrind')
  reproduce_parser.add_argument('project_name', help='name of the project')
  reproduce_parser.add_argument('fuzzer_name', help='name of the fuzzer')
  reproduce_parser.add_argument('testcase_path', help='path of local testcase')
  reproduce_parser.add_argument('fuzzer_args',
                                help='arguments to pass to the fuzzer',
                                nargs=argparse.REMAINDER)
  _add_environment_args(reproduce_parser)

  shell_parser = subparsers.add_parser(
      'shell', help='Run /bin/bash within the builder container.')
  shell_parser.add_argument('project_name', help='name of the project')
  shell_parser.add_argument('source_path',
                            help='path of local source',
                            nargs='?')
  _add_architecture_args(shell_parser)
  _add_engine_args(shell_parser)
  _add_sanitizer_args(shell_parser)
  _add_environment_args(shell_parser)

  subparsers.add_parser('pull_images', help='Pull base images.')

  args = parser.parse_args()

  if args.command == 'generate':
    return generate(args)
  if args.command == 'build_image':
    return build_image(args)
  if args.command == 'build_fuzzers':
    return build_fuzzers(args)
  if args.command == 'check_build':
    return check_build(args)
  if args.command == 'download_corpora':
    return download_corpora(args)
  if args.command == 'run_fuzzer':
    return run_fuzzer(args)
  if args.command == 'coverage':
    return coverage(args)
  if args.command == 'reproduce':
    return reproduce(args)
  if args.command == 'shell':
    return shell(args)
  if args.command == 'pull_images':
    return pull_images(args)

  return 0

if __name__ == '__main__':
    sys.exit(main())
