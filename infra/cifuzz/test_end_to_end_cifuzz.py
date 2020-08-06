import helper
import os
import tempfile
import unittest


import utils


CIFUZZ_PATH = os.path.join(helper.OSS_FUZZ_DIR, 'infra', 'cifuzz')

def run_docker_build(dockerfile, tag, path=None):
    command = ['docker', 'build']
    if path:
        command.append(path)
    command.extend([
        '--file', dockerfile, '-t', tag
    ])
    return utils.execute(command, check_result=True)


class EndToEndTest(unittest.TestCase):
    container_env_vars = {
        'OSS_FUZZ_PROJECT_NAME': 'systemd',
        'GITHUB_REPOSITORY': 'systemd',
        'GITHUB_EVENT_NAME': 'push',
        'DRY_RUN': '0',
        'ALLOWED_BROKEN_TARGETS_PERCENTAGE': '0',
        'GITHUB_ACTIONS': 'true',
        'CI': 'true',
        'GITHUB_SHA': '22e705b3073cc8d8e20039fde2143ac89df919be',
        'SANITIZER': 'address',
    }

    def run_cifuzz_container(self, name, workspace):
        command = ['docker', 'run', '--name', name, '--rm']
        container_env_vars = self.container_env_vars.copy()
        container_env_vars['GITHUB_WORKSPACE'] = workspace
        for var, value in container_env_vars.items():
            command += ['-e', '{var}={value}'.format(var=var, value=value)]

        command += ['-v', '/var/run/docker.sock:/var/run/docker.sock',
                    '-v', '{workspace}:{workspace}'.format(workspace=workspace), name]
        return utils.execute(command, check_result=True)


    def _test_end_to_end(self, tmp_dir):
        # Build cifuzz-base.
        cifuzz_base_dockerfile = os.path.join(CIFUZZ_PATH, 'cifuzz-base', 'Dockerfile')
        run_docker_build(
            cifuzz_base_dockerfile, 'gcr.io/oss-fuzz-base/cifuzz-base:latest',
            '.')

        # Build build_fuzzers and run_fuzzers
        for name in ['build_fuzzers', 'run_fuzzers']:
            path = os.path.join(CIFUZZ_PATH, 'actions', name)
            dockerfile = os.path.join(path, 'Dockerfile')
            run_docker_build(dockerfile, name, path)
            self.run_cifuzz_container(name, tmp_dir)

    def test_end_to_end(self):
        cwd = os.getcwd()
        try:
            utils.chdir_to_root()
            with tempfile.TemporaryDirectory() as tmp_dir:
                self._test_end_to_end(tmp_dir)
        finally:
            os.chdir(cwd)
