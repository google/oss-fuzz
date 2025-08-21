# OSS-Fuzz MCP


```sh
python3.12 -m venv .venv
. .venv/bin/active
python3 -m pip install -r ./requirements.txt



# Start server in one  terminal
python3 ./oss_fuzz_server.py


# Start client
python3 ./client.py fix-build --projects abseil-py
```
