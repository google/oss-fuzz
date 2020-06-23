import os
import unittest
import subprocess
import threading

from google.cloud import ndb

from main import sync_projects
from main import get_projects
from main import Project


_EMULATOR_TIMEOUT = 20
_DATASTORE_READY_INDICATOR = b'is now running'

def start_datastore_emulator():
  """Start Datastore emulator."""
  return subprocess.Popen([
      'gcloud',
      'beta',
      'emulators',
      'datastore',
      'start',
      '--consistency=1.0',
      '--host-port=localhost:' + str(os.environ.get('DATASTORE_EMULATOR_PORT')),
      '--project=' + os.environ.get('DATASTORE_PROJECT_ID'),
      '--no-store-on-disk',
  ],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)

def _wait_for_emulator_ready(proc,
                             emulator,
                             indicator,
                             timeout=_EMULATOR_TIMEOUT):
  """Wait for emulator to be ready."""
  def _read_thread(proc, ready_event):
    """Thread to continuously read from the process stdout."""
    ready = False
    while True:
      line = proc.stdout.readline()
      if not line:
        break
      if not ready and indicator in line:
        ready = True
        ready_event.set()
  # Wait for process to become ready.
  ready_event = threading.Event()
  thread = threading.Thread(target=_read_thread, args=(proc, ready_event))
  thread.daemon = True
  thread.start()
  if not ready_event.wait(timeout):
    raise RuntimeError(
        '{} emulator did not get ready in time.'.format(emulator))
  return thread

class Repository():
  def __init__(self, name, file_type, path):
    self.contents = []
    self.name = name
    self.type = file_type
    self.path = path

  def get_contents(self, path):
    if self.path == path:
      return self.contents

    for content_file in self.contents:
      if content_file.path == path:
        return content_file.contents

class TestDataSync(unittest.TestCase):
  def test_sync_projects(self):
    client = ndb.Client()

    with client.context():
      Project(name="test1").put()
      Project(name="test2").put()

      projects = {"test1", "test3"}
      sync_projects(projects)

      projects_query = Project.query()
      self.assertEqual(projects, {project.name for project in projects_query})

  def test_get_projects(self):
    repo = Repository("oss-fuzz", "dir", "projects")
    for i in range(3):
      name = "test" + str(i)
      repo.contents.append(Repository(name, "dir", "projects/" + name))
      project = repo.contents[i]
      project.contents.append(Repository("Dockerfile", "file", "placeholder"))

    # Removing Dockerfile from project test1
    repo.contents[1].contents.pop()

    self.assertEqual(get_projects(repo), {"test0", "test2"})


if __name__ == '__main__':
  ds_emulator = start_datastore_emulator()
  _wait_for_emulator_ready(ds_emulator, 'datastore',
                           _DATASTORE_READY_INDICATOR)
  unittest.main(exit=False)
  # TODO: replace this with a cleaner way of killing the process
  os.system("pkill -f datastore")
