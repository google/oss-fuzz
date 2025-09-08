# Build Analysis and Report for `base-image`

## Status

*   **Ubuntu 20.04:** CONCLUÍDO
*   **Ubuntu 24.04:** CONCLUÍDO

## Summary

Both Ubuntu 20.04 and Ubuntu 24.04 builds for `base-image` completed successfully.

## Build Logs

<details>
<summary>Ubuntu 20.04 Build Log</summary>

```
#0 building with "default" instance using docker driver

#1 [internal] load build definition from ubuntu_20_04.Dockerfile
#1 transferring dockerfile: 1.30kB done
#1 DONE 0.0s

#2 [internal] load metadata for docker.io/library/ubuntu:20.04@sha256:4a45212e9518f35983a976eead0de5eecc555a2f047134e9dd2cfc589076a00d
#2 DONE 0.3s

#3 [internal] load .dockerignore
#3 transferring context: 2B done
#3 DONE 0.0s

#4 [1/3] FROM docker.io/library/ubuntu:20.04@sha256:4a45212e9518f35983a976eead0de5eecc555a2f047134e9dd2cfc589076a00d
#4 DONE 0.0s

#5 [2/3] RUN apt-get update &&     apt-get upgrade -y &&     apt-get install -y libc6-dev binutils libgcc-9-dev tzdata &&     apt-get autoremove -y
#5 CACHED

#6 [3/3] RUN mkdir -p /out /src /work && chmod a+rwx /out /src /work
#6 CACHED

#7 exporting to image
#7 exporting layers done
#7 writing image sha256:9ef87bd615650165225994d82221490f463a62207eb9a9f82374a482b222f1b9 done
#7 naming to docker.io/library/base-image:ubuntu_20_04 done
#7 DONE 0.0s

 1 warning found (use docker --debug to expand):
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 23)
```

</details>

<details>
<summary>Ubuntu 24.04 Build Log</summary>

```
#0 building with "default" instance using docker driver

#1 [internal] load build definition from ubuntu_24_04.Dockerfile
#1 transferring dockerfile: 1.30kB done
#1 WARN: LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 23)
#1 DONE 0.0s

#2 [internal] load metadata for docker.io/library/ubuntu:24.04@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8
#2 DONE 0.0s

#3 [internal] load .dockerignore
#3 transferring context: 2B done
#3 DONE 0.0s

#4 [1/3] FROM docker.io/library/ubuntu:24.04@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8
#4 resolve docker.io/library/ubuntu:24.04@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8 done
#4 DONE 0.0s

#5 [2/3] RUN apt-get update &&     apt-get upgrade -y &&     apt-get install -y libc6-dev binutils libgcc-13-dev tzdata &&     apt-get autoremove -y
#5 CACHED

#6 [3/3] RUN mkdir -p /out /src /work && chmod a+rwx /out /src /work
#6 CACHED

#7 exporting to image
#7 exporting layers done
#7 writing image sha256:89a83332cd34693723bf1dfbf30d58deb886cd2a221aba178886168c34c741d5 done
#7 naming to docker.io/library/base-image:ubuntu_24_04 done
#7 DONE 0.0s

 1 warning found (use docker --debug to expand):
 - LegacyKeyValueFormat: "ENV key=value" should be used instead of legacy "ENV key value" format (line 23)
```

</details>
