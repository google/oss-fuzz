import os

# !!! Remove?
UPLOAD_CHUNK_SIZE = 8 * 1024 ** 2  # 8 MB.

def get_runtime_url():
  token = os.environ.get('ACTIONS_RUNTIME_TOKEN')
  if not token:
    raise Exception('Unable to get ACTIONS_RUNTIME_TOKEN env variable')
  return token

def get_work_flow_run_id():
  work_flow_run_id = os.environ.get('GITHUB_RUN_ID')
  if not work_flow_run_id:
    raise Exception('Unable to get GITHUB_RUN_ID env variable.')
  return work_flow_run_id

def get_retention_days():
  return os.environ.get('GITHUB_RETENTION_DAYS')
