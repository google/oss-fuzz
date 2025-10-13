# OSS-Fuzz MCP

This is an experimental implementation of an MCP server that enables use of
OSS-Fuzz tools. You can use it to solve various common OSS-Fuzz tasks.

At this stage, this is purely experimental code.


## Threat model for running

This is experimental code and has an open threat model. By design, the MCP server
executes untrusted code. As such, when running this tool you
should assume you will be running untrusted code on your machine. You should
only run this in a trusted environment and on a trusted network. In practice,
this means you must run this in a heavily sandboxed environment, and from a
security perspective if you run this tool you will run untrusted code in
your environment.

This code does not run in OSS-Fuzz production services and is not part of the
tooling that runs our continuous fuzzing of open source projects.

## Running the Service

```sh
python3.12 -m venv .venv
. .venv/bin/active
python3 -m pip install -r ./requirements.txt



# Start server in one  terminal
python3 ./oss_fuzz_server.py


# Start client
python3 ./client.py fix-build --projects abseil-py
```
