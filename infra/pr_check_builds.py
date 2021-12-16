# Copyright 2021 Google LLC
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
"""Helper script for checking the effects of a PR on the builds of projects"""

import os
import sys
import subprocess

def build_and_check(project_name, logdir = None):
    print("Checking %s"%(project_name))
    build_pass = False
    check_pass = False
    
    if logdir != None:
        project_logdir = os.path.join(logdir, project_name)
        project_log_stdout = os.path.join(project_logdir, "log.stdout")
        project_log_stderr = os.path.join(project_logdir, "log.stderr")

        os.mkdir(os.path.join(logdir, project_name))
        log_stdout = open(project_log_stdout, "wb")
        log_stderr = open(project_log_stderr, "wb")
    else:
        log_stdout = sys.stdout
        log_stderr = sys.stderr

    try:
        p1 = subprocess.check_call("python3 infra/helper.py build_fuzzers --engine=afl %s"%(project_name), 
                shell=True, stdout=log_stdout, stderr=log_stderr)
        build_pass = True
        p2 = subprocess.check_call("python3 infra/helper.py check_build --engine=afl %s"%(project_name), 
                shell=True, stdout=log_stdout, stderr=log_stderr)
        check_pass = True
    except:
        None
    return { "build" : build_pass, "check" : check_pass }


def get_next_logdir():
    curr_max = -1
    for file_name in os.listdir("."):
        if "logdir-" in file_name:
            try:
                file_idx = int(file_name[7:])
                if file_idx > curr_max:
                    curr_max = file_idx
            except:
                None
    return "logdir-%d"%(curr_max+1)


def run_builds_on_many(project_names):
    logdir = get_next_logdir()
    os.mkdir(logdir)

    results = dict()
    for project_name in project_names:
        results[project_name] = build_and_check(project_name, logdir)

    # Print results
    print("Results:")
    for project_name in project_names:
        print("%s : { build: %s, check: %s }"%(project_name, 
                str(results[project_name]['build']),
                str(results[project_name]['check'])))

    # Write the results
    results_file = os.path.join(logdir, "results.txt")
    with open(results_file, "w") as rf:
        for project_name in results:
            rf.write("%s : { build: %s, check: %s }\n"%(project_name, 
                str(results[project_name]['build']),
                str(results[project_name]['check'])))
    return results

def clear_project(project_name):
    """
    Deletes the build/out/PROJ_NAME folder of a given OSS-Fuzz project.
    Notice this function uses rm -rf on a project name, so please ensure 
    the project names you provide are valid and you don't for some reason
    trigger rm -rf of data you're not willing to delete.
    """
    # Do a bit of checking to make sure we're in the oss-fuzz base folder
    folders_to_check = [
            './projects', './infra', './projects/binutils'
            ]
    for folder in folders_to_check:
        if not os.path.isdir(folder):
            print("%s not found, are you in the right place?"%(folder))
            exit(0)
    if not os.path.isdir("./build/out/%s"%(project_name)):
        return
    subprocess.check_call("rm -rf ./build/out/%s"%(project_name), shell=True)


def clear_all_projects(project_names):
    # Clear all builds for each project
    for project in project_names:
        clear_project(project)


def diff_results(results_pre_pr, results_post_pr):
    print("[+] diffing")
    diff_results = dict()
    for project_name in results_pre_pr:
        consistent_result = True
        if results_pre_pr[project_name] != results_post_pr[project_name]:
            consistent_result = False
        diff_results[project_name] = "pass" if consistent_result else "fail"

    for project_name in diff_results:

        print("%s - %s"%(project_name, diff_results[project_name]))


def full_roundtrip(git_pull_request_id, project_names):
    """
    Builds projects pre and post a given PR, and does a simple
    diff on the results from build_fuzzers and check_build.
    """
    basedir = os.getcwd()

    # Run builds pre PR
    print("[+] Doing a pre-pr check")
    subprocess.check_call("git clone https://github.com/google/oss-fuzz oss-fuzz", shell=True)
    os.chdir("oss-fuzz")
    # Clone a clean 
    #clear_all_projects(project_names)
    results_pre_pr = run_builds_on_many(project_names)

    # Checkout PR and build all images
    os.chdir(basedir)
    subprocess.check_call("git clone https://github.com/google/oss-fuzz oss-fuzz-new-pr", shell=True)
    os.chdir("oss-fuzz-new-pr")

    git_checkout_pr = "git fetch origin pull/%d/head"%(git_pull_request_id)
    subprocess.check_call(git_checkout_pr, shell=True)
    subprocess.check_call("git checkout FETCH_HEAD", shell=True)
    subprocess.check_call("./infra/base-images/all.sh", shell=True)

    # Run builds post PR 
    print("[+] Doing a post-pr check")
    clear_all_projects(project_names)
    results_post_pr = run_builds_on_many(project_names)

    # Diff the results
    diff_results(results_pre_pr, results_post_pr)

if __name__ == "__main__":
    full_roundtrip(7026, ['jsoncons', 'fluent-bit', 'binutils', 'hermes', 'cjson'])
