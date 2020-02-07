#!/usr/bin/env python3
"""Script for automating analysis of the dataflow strategy in ClusterFuzz."""
# TODO(Dor1s): consider breaking this up into pieces that can be re-used.
import datetime
import json
import os
import sys

from google.cloud import bigquery
from google.cloud import storage

# Looking at the date over the past 14 days, as that's how long our logs exist.
_DAYS_TO_ANALYZE = 2

_BQ_CLIENT = bigquery.Client(project='clusterfuzz-external')
_GCS_CLIENT = storage.Client(project='clusterfuzz-external')

_QUERY_BASE = """
    CREATE TEMP FUNCTION
  TimeIsRight(timestamp FLOAT64) AS ( timestamp >= UNIX_SECONDS(TIMESTAMP("{start_time}"))
    AND timestamp < UNIX_SECONDS(TIMESTAMP("{end_time}")) );
SELECT
  fuzz_target,
  edges_without_strategy,
  edges_with_strategy,
  edges_with_strategy - edges_without_strategy AS edge_diff,
  features_without_strategy,
  features_with_strategy,
  runs_without_strategy,
  runs_with_strategy,
  edge_coverage_without_strategy,
  edge_coverage_with_strategy,
  command
FROM (
    # Only the fuzzers that used the strategy in the given timeframe.
    # Important for strategies that are not applicable to all fuzzers.
  SELECT
    fuzzer AS fuzz_target,
    ANY_VALUE(command) as command,
  FROM
    `libFuzzer_stats.TestcaseRun`
  WHERE
    # Important to check that the strategy is ON here.
    strategy_dataflow_tracing = 1
    AND TimeIsRight(timestamp)
  GROUP BY
    fuzzer ) fuzzers_affected
JOIN (
  SELECT
    fuzzer,
    AVG(new_edges) AS edges_without_strategy,
    AVG(new_features) AS features_without_strategy,
    MAX(edge_coverage) AS edge_coverage_without_strategy,
    COUNT(1) AS runs_without_strategy,
  FROM
    `libFuzzer_stats.TestcaseRun`
  WHERE
    # Check that the strategy is OFF below.
    (strategy_dataflow_tracing = 0
      OR strategy_dataflow_tracing IS NULL)
    AND TimeIsRight(timestamp)
  GROUP BY
    fuzzer ) without_strategy
ON
  fuzzers_affected.fuzz_target = without_strategy.fuzzer
JOIN (
  SELECT
    fuzzer,
    AVG(new_edges) AS edges_with_strategy,
    AVG(new_features) AS features_with_strategy,
    MAX(edge_coverage) AS edge_coverage_with_strategy,
    COUNT(1) AS runs_with_strategy,
  FROM
    `libFuzzer_stats.TestcaseRun`
  WHERE
    # Check that the strategy is ON below.
    strategy_dataflow_tracing = 1
    AND TimeIsRight(timestamp)
  GROUP BY
    fuzzer ) with_strategy
ON
  fuzzers_affected.fuzz_target = with_strategy.fuzzer
ORDER BY
  fuzz_target
"""

_COVERAGE_BUCKET = 'oss-fuzz-coverage'
_COVERAGE_PATH = '{project}/fuzzer_stats/{date}/{binary}.json'
_COVERAGE_REPORT = ('https://storage.googleapis.com/oss-fuzz-coverage/'
                    '{project}/reports/{date}/linux/report.html')
_BINARY_PATH_TOKEN = '/mnt/scratch0/clusterfuzz/bot/builds/clusterfuzz-builds'
_LOG_BUCKET = '{project}-logs.clusterfuzz-external.appspot.com'
_LOG_PATH = '{fuzz_target}/{job}/{date_slash_time}.log'

_ONE_DAY = datetime.timedelta(days=1)


def _date_str(date):
  return date.strftime('%Y-%m-%d %H:%M:%S')


def _daily_stats(day):
  start_time = _date_str(day)
  end_time = _date_str(day + _ONE_DAY)
  query = _QUERY_BASE.format(start_time=start_time, end_time=end_time)
  return _BQ_CLIENT.query(query)


def _is_interesting(row):
  if row['edges_without_strategy'] > row['edges_with_strategy']:
    return False

  if row['edges_without_strategy'] != 0:
    return False

  if row['edge_coverage_without_strategy'] == 0:
    return False

  if row['edge_coverage_without_strategy'] >= row['edge_coverage_with_strategy']:
    return False

  return True


def _project_name(fuzz_target):
  name_parts = fuzz_target.split('_')
  assert len(name_parts) > 2
  return name_parts[1]


def _binary_name(command):
  for c in command:
    if ',' not in c and _BINARY_PATH_TOKEN in c:
      return os.path.basename(c)
  assert False
  return None


def _coverage_date_str(date):
  return date.strftime('%Y%m%d')


def _compare_files(base, advanced, factor):
  assert base['filename'] == advanced['filename']
  value_base = base['summary'][factor]['covered']
  value_advanced = advanced['summary'][factor]['covered']
  return value_advanced - value_base


def _calculate_coverage_diff(coverage_base, coverage_advanced):
  base = json.loads(coverage_base)
  advanced = json.loads(coverage_advanced)
  files_base = base['data'][0]['files']
  files_advanced = advanced['data'][0]['files']
  idx1, idx2 = 0, 0
  result = []

  while idx1 < len(files_base) and idx2 < len(files_advanced):
    if files_base[idx1]['filename'] == files_advanced[idx2]['filename']:
      delta = {}
      for factor in ['functions', 'lines', 'regions']:
        delta[factor] = _compare_files(files_base[idx1], files_advanced[idx2],
                                       factor)

      filename = files_base[idx1]['filename']
      result.append({
          'filename': filename,
          'functions': delta['functions'],
          'lines': delta['lines'],
          'regions': delta['regions'],
      })

      if any(delta.values()):
        print('diffs: func: %4d, line: %4d, region: %4d in %s' %
              (delta['functions'], delta['lines'], delta['regions'], filename))

      idx1 += 1
      idx2 += 1
    elif files_base[idx1]['filename'] < files_advanced[idx2]['filename']:
      print('Only in base: %s', files_base[idx1]['filename'])
      idx1 += 1
    else:
      print('Only in advanced: %s', files_advanced[idx2]['filename'])
      idx2 += 1

  if idx1 < len(files_base):
    for f in files_base[idx1:]:
      print('Only in base: %s', f['filename'])

  if idx2 < len(files_advanced):
    for f in files_advanced[idx2:]:
      print('Only in advanced: %s', f['filename'])

  return result


def _coverage_report(project, day):
  return _COVERAGE_REPORT.format(project=project, date=_coverage_date_str(day))


def _get_coverage_diff(row, day):
  project = _project_name(row['fuzz_target'])
  binary = _binary_name(row['command'])
  path_base = _COVERAGE_PATH.format(project=project,
                                    date=_coverage_date_str(day - _ONE_DAY),
                                    binary=binary)
  path_advanced = _COVERAGE_PATH.format(project=project,
                                        date=_coverage_date_str(day),
                                        binary=binary)
  coverage_base = _read_gcs_file(_COVERAGE_BUCKET, path_base)
  coverage_advanced = _read_gcs_file(_COVERAGE_BUCKET, path_advanced)
  if not coverage_base or not coverage_advanced:
    return False
  diff = _calculate_coverage_diff(coverage_base, coverage_advanced)
  if any(delta.values() for delta in diff):
    print('There is a visible coverage difference. Explore the reports:')
    print(' old: ' + _coverage_report(project, day - _ONE_DAY))
    print(' new: ' + _coverage_report(project, day))
    return True
  return False


def _read_gcs_file(bucket_name, path):
  bucket = _GCS_CLIENT.bucket(bucket_name)
  blob = bucket.get_blob(path)
  if not blob:
    print('WARNING: failed to read gs://%s/%s' % (bucket_name, path))
    return b''
  return blob.download_as_string()


_DFT_TOKENS = [
    b'AUTOFOCUS',
    b'DataFlowTrace',
    b'the focus function',
    b'Data Flow Trace',
]


def _get_log(project, row):
  date_and_time = datetime.datetime.utcfromtimestamp(row['timestamp'])
  date_slash_time = date_and_time.isoformat().replace('T',
                                                      '/').replace('.', ':')
  #date_slash_time = date_slash_time[::-1].replace('.', ':', 1)[::-1]
  bucket = _LOG_BUCKET.format(project=project)
  path = _LOG_PATH.format(fuzz_target=row['fuzzer'],
                          job=row['job'],
                          date_slash_time=date_slash_time)
  log_data = _read_gcs_file(bucket, path)

  print('##### Parsing log: gs://%s/%s' % (bucket, path))
  for line in log_data.splitlines():
    if any(line.count(token) for token in _DFT_TOKENS):
      print(line)

  return log_data


_QUERY_RUNS = """
    CREATE TEMP FUNCTION
  TimeIsRight(timestamp FLOAT64) AS ( timestamp >= UNIX_SECONDS(TIMESTAMP("{start_time}"))
    AND timestamp < UNIX_SECONDS(TIMESTAMP("{end_time}")) );
SELECT
  timestamp,
  new_edges,
  fuzzer,
  job
FROM `libFuzzer_stats.TestcaseRun`
WHERE
    # Important to check that the strategy is ON here.
    strategy_dataflow_tracing = 1
    AND TimeIsRight(timestamp)
    AND fuzzer="{fuzz_target}"
    AND new_edges > 0
"""


def _find_runs(fuzz_target, day):
  start_time = _date_str(day - _ONE_DAY)
  end_time = _date_str(day + _ONE_DAY)
  query = _QUERY_RUNS.format(start_time=start_time,
                             end_time=end_time,
                             fuzz_target=fuzz_target)
  runs = _BQ_CLIENT.query(query)
  for row in runs:
    log_data = _get_log(_project_name(fuzz_target), row)


def main():
  today = datetime.date.today() + _ONE_DAY
  for i in range(1, _DAYS_TO_ANALYZE):
    print('=' * 80)
    day = today - datetime.timedelta(days=i)
    print('Analyzing stats for ' + str(day))
    stats = _daily_stats(day)
    for row in stats:
      if _is_interesting(row):
        print('-' * 80)
        print(row['fuzz_target'], row['edges_without_strategy'],
              row['edges_with_strategy'], row['edge_coverage_without_strategy'],
              row['edge_coverage_with_strategy'])
        if (_get_coverage_diff(row, day)):
          _find_runs(row['fuzz_target'], day)


if __name__ == "__main__":
  main()
