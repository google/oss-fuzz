#!/usr/bin/python3
# Copyright 2022 Google LLC
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
"""Fuzz grpc server using the Greeter example"""

import os
import sys
import time
import grpc
from google.protobuf import any_pb2
from google.rpc import status_pb2
from grpc_status import rpc_status

import socket
import atheris
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor
from google.protobuf.internal import builder as _builder

# Extract path of fuzzer so we can include protobuf modules
if getattr(sys, 'frozen', False):
    app_path = os.path.dirname(sys.executable)
elif __file__:
    app_path = os.path.dirname(__file__)
else:
    raise Exception("Could not extract path needed to import loop.py")
sys.path.append(app_path)

import helloworld_pb2
import helloworld_pb2_grpc

runs_left = None
server = None

# Simple server
class FuzzGreeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        print("In server")
        return helloworld_pb2.HelloReply(message='Hello from fuzz server, %s!' % request.name)


def serve() -> None:
    """Starts fuzz server"""
    global server
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(FuzzGreeter(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    #server.wait_for_termination()
    return

@atheris.instrument_func
def TestInput(input_bytes):
    """Send fuzzing input to the server"""
    global runs_left
    global server
    if runs_left != None:
        runs_left = runs_left - 1
        if runs_left <= 2:
            server.stop()
            return

    time.sleep(0.02)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("localhost", 50051))
            s.sendall(input_bytes)
            data = s.recv(1024)
    except OSError:
        # We don't want to report network errors
        return

    # Hit the rpc_status too
    fdp = atheris.FuzzedDataProvider(input_bytes)
    try:
        rich_status = status_pb2.Status(
            code=fdp.ConsumeIntInRange(1,30000),
            message=fdp.ConsumeUnicodeNoSurrogates(60)
        )
        rpc_status.to_status(rich_status)
    except ValueError:
        pass

    return


def get_run_count_if_there():
    """Ensure proper exit for coverage builds"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-atheris_runs", required=False, default=None)
    args, _ = parser.parse_known_args()
    if args.atheris_runs is None:
        print("None args")
        return None
    print(f"Got a fixed set of runs {args.atheris_runs}")
    return args.atheris_runs


def main():
    global runs_left
    max_runs = get_run_count_if_there()
    if max_runs is not None:
        runs_left = int(max_runs)

    # Launch a grpc server
    serve()

    # Start fuzzing
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
