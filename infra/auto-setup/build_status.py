#!/usr/bin/env python

import codecs
import datetime
import os
import subprocess

import jenkins
import jinja2
from jinja2 import Environment, FileSystemLoader

JENKINS_SERVER = ('localhost', 8080)
LOGS_BUCKET = 'oss-fuzz-build-logs'

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class Result(object):
  """Result."""

  def __init__(self, name, output):
    self.name = name
    self.output = output


def get_build_results(server):
  """Return successes, failures."""
  successes = []
  failures = []

  for job in server.get_jobs(1):
    try:
      name = job['fullname']
      if not name.startswith('projects/'):
        continue

      print name
      project = name[len('projects/'):]

      info = server.get_job_info(name)
      last_build_number = info['lastCompletedBuild']['number']
      last_failed_builder_number = info['lastFailedBuild']['number']

      if last_build_number == last_failed_builder_number:
        failures.append(Result(
            project,
            server.get_build_console_output(name, last_build_number)))
      else:
        successes.append(Result(
            project,
            server.get_build_console_output(name, last_build_number)))
    except Exception:
      pass

  return successes, failures


def upload_status(successes, failures):
  """Upload main status page."""
  env = Environment(loader=FileSystemLoader(os.path.join(SCRIPT_DIR,
                                                         'templates')))
  with open('status.html', 'w') as f:
    f.write(
      env.get_template('status_template.html').render(
          failures=failures, successes=successes,
          last_updated=datetime.datetime.utcnow().ctime()))

  subprocess.check_output(['gsutil', 'cp', 'status.html', 'gs://' +
                           LOGS_BUCKET], stderr=subprocess.STDOUT)


def upload_build_logs(successes, failures):
  """Upload individual build logs."""
  for result in failures + successes:
    with codecs.open('latest.txt', 'w', encoding='utf-8') as f:
      f.write(result.output)

    subprocess.check_output(['gsutil', 'cp', 'latest.txt',
                             'gs://%s/build_logs/%s/' %
                             (LOGS_BUCKET, result.name)],
                             stderr=subprocess.STDOUT)


def main():
  jenkins_login = get_jenkins_login()
  server = jenkins.Jenkins('http://%s:%d' % JENKINS_SERVER,
                           username=jenkins_login[0], password=jenkins_login[1])

  successes, failures = get_build_results(server)
  upload_status(successes, failures)
  upload_build_logs(successes, failures)


def get_jenkins_login():
  """Returns (username, password) for jenkins."""
  username = os.getenv('JENKINS_USER')
  password = os.getenv('JENKINS_PASS')
  return username, password


if __name__ == '__main__':
  main()
