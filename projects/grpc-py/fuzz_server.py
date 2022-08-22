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

import sys
import time
import grpc
import socket
import atheris
import threading
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


# Simple server
class FuzzGreeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        print("In server")
        return helloworld_pb2.HelloReply(message='Hello from fuzz server, %s!' % request.name)


def serve() -> None:
    """Starts fuzz server"""
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(FuzzGreeter(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()
    return


def TestInput(input_bytes):
   """Send fuzzing input to the server"""
   time.sleep(0.02)
   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect(("localhost", 50051))
      s.sendall(input_bytes)
      data = s.recv(1024)
   return


def main():
   # Launch a grpc server
   _thread = threading.Thread(target=serve)
   _thread.start()
   time.sleep(0.2)

   # Start fuzzing
   atheris.instrument_all()
   atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
   atheris.Fuzz()


if __name__ == "__main__":
   main()
