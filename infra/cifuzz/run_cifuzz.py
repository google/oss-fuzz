import os
import tempfile

DEFAULT_ENVS = [
    ('DRY_RUN', '0'),
    ('SANITIZER', 'address')
]

REQUIRED_ENVS = [
    'PROJECT_SRC_PATH',
    'WORKSPACE'
]

def set_default_env_var_if_unset(env_var, default_value):
    if env_var not in os.environ:
        os.environ[env_var] = default_value



def docker_run(name, workdir):
    command = ['docker', 'run', '--name', name, '--rm', '-e', 'PROJECT_SRC_PATH',
               '-e', 'BUILD_INTEGRATION_PATH',
               '-e', 'OSS_FUZZ_PROJECT_NAME', '-e', 'GITHUB_WORKSPACE', '-e', 'GITHUB_EVENT_NAME', '-e', 'GITHUB_REPOSITORY', '-e', 'GITHUB_EVENT_NAME', '-e', 'DRY_RUN', '-e', 'CI', '-e', 'SANITIZER', '-e', 'GITHUB_SHA', '-v', '$PROJECT_SRC_PATH:$PROJECT_SRC_PATH', '-v', '/var/run/docker.sock:/var/run/docker.sock', '-v', f'{workdir}:{workdir}', f'gcr.io/oss-fuzz-base/{name}']
    subprocess.run(command, check=True)


def main():
    for env_var, default_value in DEFAULT_ENVS:
        set_default_env_var_if_unset(env_var, default_value)

    for env_var in REQUIRED_ENVS:
        assert os.environ.get(env_var) is not None, f'{env_var} not set'

    with tempfile.TemporaryDirectory() as temp_dir:
        os.environ['GITHUB_WORKSPACE'] = temp_dir
        docker_run('build_fuzzers', workdir)




if __name__ == '__main__':
    main()
