# OSS-Fuzz agent skills

Skills that can be easily used with agents e.g. gemini CLI.


# Threat model for running
This is experimental code and has an open threat model. By design, the agents execute untrusted code and are running in "dangerous"/"yolo" modes. As such, when running this tool you should assume you will be running untrusted code on your machine. You should only run this in a trusted environment and on a trusted network. In practice, this means you must run this in a heavily sandboxed environment, and from a security perspective if you run this tool you will run untrusted code in your environment.

This code does not run in OSS-Fuzz production services and is not part of the tooling that runs our continuous fuzzing of open source projects.