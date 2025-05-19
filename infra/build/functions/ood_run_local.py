import logging
import os
import pprint
import shutil
import subprocess
import sys
import tempfile
import time

import build_project
import fuzzbench

GCB_WORKSPACE_DIR = '/workspace'
FUZZBENCH_PATH = '/fuzzbench'
DOCKER_BUILDER_IMAGE = 'gcr.io/cloud-builders/docker'
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'ood_run_local_log.txt')

def set_log_config(log_file_path):
    with open(log_file_path, 'w'):
      pass
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(message)s'
    )


def check_docker_running():
    """Checks if the Docker daemon is accessible."""
    try:
        subprocess.run(['docker', 'info'], check=True, capture_output=True)
        logging.info("Docker daemon is running.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.info("Error: Docker daemon does not seem to be running or accessible.")
        logging.info(f"Details: {e}")
        return False


def run_step_locally(temp_dir, local_workspace_path, local_fuzzbench_path, step, i):
    logging.info(f"--- Step {i}: ---")
    logging.info(f'Step_details:\n{step}')
    logging.info("------")

    image_name = step.get('name')
    args = step.get('args', [])
    env_list = step.get('env', [])
    volumes = step.get('volumes', [])

    if not image_name:
        raise Exception(f"Error: Step {i} has no 'name' field.")
    if not args:
        raise Exception(f"Error: Step {i} has no 'args' field.")
    if args[0] == "push":
        logging.info(f"Skipping step {i} because it is a push step.")
        return
    if image_name == 'google/cloud-sdk':
        logging.info(f"Skipping step {i} because it needs GCB service account.")
        return
    if 'python' in image_name:
        logging.info(f"Skipping step {i} because it will try to upload the testcase.")
        return
    if 'python' in args[0]:
        logging.info(f"Skipping step {i} because it will try to upload corpus.")
        return


    step_container_work_dir = GCB_WORKSPACE_DIR + '/' + step.get('dir', '')

    if args[0] == 'run' and args[1] == '-v':
        args[2] = args[2].replace(GCB_WORKSPACE_DIR, temp_dir, 1)

    docker_command = ['docker', 'run', '--rm', '--cpus=0.5']
    docker_command.extend(['-w', step_container_work_dir])
    docker_command.extend(['-v', f'{local_workspace_path}:{GCB_WORKSPACE_DIR}'])

    mount_fuzzbench = any(vol.get('path') == FUZZBENCH_PATH for vol in volumes)
    if mount_fuzzbench:
        docker_command.extend(['-v', f'{local_fuzzbench_path}:{FUZZBENCH_PATH}'])

    if image_name == DOCKER_BUILDER_IMAGE:
        docker_command.extend(['-v', '/var/run/docker.sock:/var/run/docker.sock'])

    for env_var in env_list:
        docker_command.extend(['-e', env_var])

    docker_command.append(image_name)
    if '-runs=0 -artifact_prefix=' in args[-1]:
        docker_command += ['timeout', '10']
    docker_command.extend(args)

    if 'https://github.com/google/oss-fuzz.git' in docker_command:
        oss_fuzz_dir = os.path.dirname(os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        docker_command = [
            'cp',
            '-r',
            f'{oss_fuzz_dir}',
            f'{temp_dir}'
        ]

    #TODO Replace if with generic conditions applied to all steps
    # Maybe change the step itself in fuzzbench.py
    if '$$' in docker_command[-1]:
        docker_command[-1] = docker_command[-1].replace("$$SRC", '"$SRC"')
        docker_command[-1] = docker_command[-1].replace("$${OUT}", '"$OUT"')

    logging.info(f"Executing Docker Command:")
    logging.info(' '.join(map(lambda x: f'"{x}"' if ' ' in x else x, docker_command)))

    if i == 18:
        zzz = 1

    try:
        start_time = time.time()
        result = subprocess.run(
            docker_command,
            check=True,
            capture_output=True,
            text=True
        )
        end_time = time.time()
        logging.info("--- Container STDOUT ---")
        logging.info(result.stdout)
        logging.info("--- Container STDERR ---")
        logging.info(result.stderr)
        logging.info(f"--- Step {i} completed successfully --- Took {end_time - start_time}s\n")
    except subprocess.CalledProcessError as e:
        if e.returncode == 124:
          end_time = time.time()
          logging.info(f"Caught timeout: {e}")
          logging.info(f"--- Step {i} completed with a timeout --- Took {end_time - start_time}s\n")
        else:
            logging.info("--- DOCKER RUN ERROR ---")
            logging.info(f"Docker command failed with exit code {e.returncode}")
            logging.info("--- Container STDOUT ---")
            logging.info(e.stdout)
            logging.info("--- Container STDERR ---")
            logging.info(e.stderr)
            logging.info(f"Failed Step Details: {step}")
            logging.info(f"Failed Docker Command: {' '.join(docker_command)}")
            sys.exit(f"Execution failed at step {i}")
    except Exception as e:
        logging.info("--- UNEXPECTED ERROR ---")
        logging.info(f"An unexpected error occurred during step {i}: {e}")
        logging.info(f"Failed Step Details: {step}")
        logging.info(f"Failed Docker Command: {' '.join(docker_command)}")
        sys.exit(f"Execution failed at step {i}")

def remove_temp_dir_content(temp_dir, local_workspace_path, i):
    remove_temp_dir_step = {
        'name': 'bash', 
        'args': ['sh', '-c', f'rm -rf {GCB_WORKSPACE_DIR}/*']
    }
    run_step_locally(temp_dir, local_workspace_path, '', remove_temp_dir_step, i)


def run_steps_locally(steps, temp_dir=None, log_file_path=LOG_FILE_PATH, testing=False):
    """Executes Cloud Build steps locally by running each step's command
    inside the specified container using 'docker run'."""
    #TODO Avoid sudo requirement for removing temp_dir
    set_log_config(log_file_path)

    if not steps:
        logging.info("No steps provided to run.")
        return
    if not check_docker_running():
        logging.info("Docker is required.")
        sys.exit(1)

    logging.info(f"--- Starting Local Execution with Docker ---")

    if not temp_dir:
        temp_dir = tempfile.mkdtemp()
    local_workspace_path = temp_dir
    local_fuzzbench_path = os.path.join(temp_dir, 'fuzzbench_vol')
    os.makedirs(local_fuzzbench_path, exist_ok=True)

    for i, step in enumerate(steps):
        run_step_locally(temp_dir, local_workspace_path, local_fuzzbench_path, step, i)
    logging.info(f"--- Local Execution Finished ---")
    if not testing:
        logging.info(f"--- Starting temporary directory removal ---")
        remove_temp_dir_content(temp_dir, local_workspace_path, local_fuzzbench_path, i+1)
        shutil.rmtree(temp_dir)
        logging.info(f"--- Removed temporary directory ---")


def main():
  """Build and run locally fuzzbench for OSS-Fuzz projects."""
  args = ['libucl', '--fuzzing-engine', 'mopt', '--branch',
          'ood_upload_testcase', '--fuzz-target', 'ucl_add_string_fuzzer']
  steps_to_run_locally = build_project.build_script_main(
        'Does a FuzzBench run locally.', fuzzbench.get_build_steps,
        fuzzbench.FUZZBENCH_BUILD_TYPE, args=args, ood_local_run=True)

  run_steps_locally(steps_to_run_locally)

  return 0


if __name__ == '__main__':
  sys.exit(main())