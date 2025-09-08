# Build Analysis and Report for `base-builder`

## Status

*   **Ubuntu 20.04:** CONCLUÍDO
*   **Ubuntu 24.04:** CONCLUÍDO

## Summary

The Ubuntu 20.04 build for `base-builder` completed successfully.
The Ubuntu 24.04 build for `base-builder` initially failed due to an issue with the base image not being found and a syntax error in the Dockerfile. After correcting the `FROM` instruction to use a local image and fixing the `ADD` instruction, the build was successful.

## Build Logs

<details>
<summary>Ubuntu 20.04 Build Log</summary>

```
#0 building with "default" instance using docker driver

#1 [internal] load build definition from ubuntu_20_04.Dockerfile
#1 transferring dockerfile: 9.67kB done
#1 DONE 0.0s

#2 [internal] load metadata for gcr.io/oss-fuzz-base/base-clang:ubuntu_20_04
#2 DONE 0.0s

#3 [internal] load metadata for gcr.io/oss-fuzz-base/indexer:latest
#3 DONE 0.4s

#4 [internal] load .dockerignore
#4 transferring context: 2B done
#4 DONE 0.0s

#5 FROM gcr.io/oss-fuzz-base/indexer:latest@sha256:0b3c8d6be91227d926b87fb13971a3385f751e0cc61684136a148aa8d04d48cb
#5 DONE 0.0s

#6 [stage-0  1/32] FROM gcr.io/oss-fuzz-base/base-clang:ubuntu_20_04
#6 DONE 0.0s

#7 [internal] load build context
#7 transferring context: 4.24kB done
#7 DONE 0.0s

#8 [stage-0 22/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc2 /usr/local/bin/
#8 DONE 0.1s

#9 [stage-0 23/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc2 /usr/local/bin
#9 DONE 0.1s

#10 [stage-0 21/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc /usr/local/bin
#10 DONE 0.1s

#11 [stage-0 20/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc /usr/local/bin/
#11 DONE 0.1s

#12 [stage-0 11/32] RUN precompile_afl
#12 CACHED

#13 [stage-0  7/32] RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.9.0/bazelisk-linux-amd64 -o /usr/local/bin/bazel &&     chmod +x /usr/local/bin/bazel
#13 CACHED

#14 [stage-0 19/32] COPY bazel_build_fuzz_tests     cargo     compile     compile_afl     compile_centipede     compile_honggfuzz     compile_fuzztests.sh     compile_go_fuzzer     compile_javascript_fuzzer     compile_libfuzzer     compile_native_go_fuzzer     compile_native_go_fuzzer_v2     go_utils.sh     compile_python_fuzzer     debug_afl     install_go.sh     install_javascript.sh     install_java.sh     install_python.sh     install_ruby.sh     install_rust.sh     install_swift.sh     make_build_replayable.py     python_coverage_helper.py     replay_build.sh     srcmap     write_labels.py     unshallow_repos.py     /usr/local/bin/
#14 CACHED

#15 [stage-0 12/32] RUN cd /src &&     curl -L -O https://github.com/google/honggfuzz/archive/oss-fuzz.tar.gz &&     mkdir honggfuzz &&     cd honggfuzz &&     tar -xz --strip-components=1 -f /src/oss-fuzz.tar.gz &&     rm -rf examples /src/oss-fuzz.tar.gz
#15 CACHED

#16 [stage-0  9/32] RUN git clone https://github.com/AFLplusplus/AFLplusplus.git aflplusplus &&     cd aflplusplus &&     git checkout daaefcddc063b356018c29027494a00bcfc3e240 &&     wget --no-check-certificate -O oss.sh https://raw.githubusercontent.com/vanhauser-thc/binary_blobs/master/oss.sh &&     rm -rf .git &&     chmod 755 oss.sh
#16 CACHED

#17 [stage-0 29/32] RUN cd /tmp && git clone https://github.com/NixOS/patchelf &&     apt-get update && apt-get install -y autoconf &&     cd patchelf && git checkout 523f401584d9584e76c9c77004e7abeb9e6c4551 &&     unset CFLAGS && export CXXFLAGS='-stdlib=libc++' && export LDFLAGS='-lpthread' &&     ./bootstrap.sh && ./configure && make &&     cp /tmp/patchelf/src/patchelf /usr/local/bin &&     rm -rf /tmp/patchelf && apt-get remove -y autoconf
#17 CACHED

#18 [stage-0  4/32] RUN PYTHON_DEPS="        zlib1g-dev         libncurses5-dev         libgdbm-dev         libnss3-dev         libssl-dev         libsqlite3-dev         libreadline-dev         libffi-dev         libbz2-dev         liblzma-dev" &&     unset CFLAGS CXXFLAGS &&     apt-get install -y $PYTHON_DEPS &&     cd /tmp &&     curl -O https://www.python.org/ftp/python/3.11.13/Python-3.11.13.tar.xz &&     tar -xvf Python-3.11.13.tar.xz &&     cd Python-3.11.13 &&     ./configure --enable-optimizations --enable-shared &&     make -j$(nproc) &&     make install &&     ldconfig &&     ln -s /usr/local/bin/python3 /usr/local/bin/python &&     cd .. &&     rm -r /tmp/Python-3.11.13.tar.xz /tmp/Python-3.11.13 &&     rm -rf /usr/local/lib/python3.11/test &&     python3 -m ensurepip &&     python3 -m pip install --upgrade pip &&     apt-get remove -y $PYTHON_DEPS # https://github.com/google/oss-fuzz/issues/3888
#18 CACHED

#19 [stage-0 25/32] COPY llvmsymbol.diff /src
#19 CACHED

#20 [stage-0 26/32] COPY detect_repo.py /opt/cifuzz/
#20 CACHED

#21 [stage-0 21/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc /usr/local/bin
#21 CACHED

#22 [stage-0 13/32] COPY precompile_honggfuzz /usr/local/bin/
#22 CACHED

#23 [stage-0 30/32] COPY indexer /opt/indexer
#23 CACHED

#24 [stage-0 24/32] RUN chmod +x /usr/local/bin/clang-jcc /usr/local/bin/clang++-jcc /usr/local/bin/clang-jcc2 /usr/local/bin/clang++-jcc2
#24 CACHED

#25 [stage-0 22/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc2 /usr/local/bin/
#25 CACHED

#26 [stage-0 27/32] COPY bazel.bazelrc /root/.bazelrc
#26 CACHED

#27 [stage-0 10/32] COPY precompile_afl /usr/local/bin/
#27 CACHED

#28 [stage-0 20/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc /usr/local/bin/
#28 CACHED

#29 [stage-0 15/32] RUN cd /src &&     git clone https://github.com/google/fuzztest &&     cd fuzztest &&     git checkout a37d133f714395cabc20dd930969a889495c9f53 &&     rm -rf .git
#29 CACHED

#30 [stage-0 17/32] RUN precompile_centipede
#30 CACHED

#31 [stage-0  8/32] WORKDIR /src
#31 CACHED

#32 [stage-0 16/32] COPY precompile_centipede /usr/local/bin/
#32 CACHED

#33 [stage-0 31/32] COPY --from=gcr.io/oss-fuzz-base/indexer /indexer/build/indexer /opt/indexer/indexer
#33 CACHED

#34 [stage-0  3/32] RUN /install_deps.sh && rm /install_deps.sh
#34 CACHED

#35 [stage-0 23/32] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc2 /usr/local/bin
#35 CACHED

#36 [stage-0  2/32] COPY install_deps.sh /
#36 CACHED

#37 [stage-0  6/32] RUN unset CFLAGS CXXFLAGS && pip3 install -v --no-cache-dir     six==1.15.0 absl-py==2.3.0 pyelftools==0.32 && rm -rf /tmp/*
#37 CACHED

#38 [stage-0 14/32] RUN precompile_honggfuzz
#38 CACHED

#39 [stage-0 28/32] RUN mkdir -p /ccache/bin && mkdir -p /ccache/cache &&     ln -s /usr/local/bin/ccache /ccache/bin/clang &&     ln -s /usr/local/bin/ccache /ccache/bin/clang++ &&     ln -s /usr/local/bin/ccache /ccache/bin/clang-jcc &&     ln -s /usr/local/bin/ccache /ccache/bin/clang++-jcc
#39 CACHED

#40 [stage-0  5/32] RUN cd /tmp && curl -OL https://github.com/ccache/ccache/releases/download/v4.10.2/ccache-4.10.2.tar.xz &&     tar -xvf ccache-4.10.2.tar.xz && cd ccache-4.10.2 &&     mkdir build && cd build &&     export LDFLAGS='-lpthread' &&     cmake -D CMAKE_BUILD_TYPE=Release .. &&     make -j && make install &&     rm -rf /tmp/ccache-4.10.2 /tmp/ccache-4.10.2.tar.xz
#40 CACHED

#41 [stage-0 18/32] COPY sanitizers /usr/local/lib/sanitizers
#41 CACHED

#42 [stage-0 32/32] RUN chmod a+x /opt/indexer/indexer /opt/indexer/index_build.py
#42 CACHED

#43 exporting to image
#43 exporting layers done
#43 writing image sha256:07a7ae325e252ea68c48c1719e0db3c04580a0a2046ad5f457ce3bcb2907ad32 done
#43 naming to docker.io/library/base-builder:ubuntu_20_04 done
#43 DONE 0.0s

```

</details>

<details>
<summary>Ubuntu 24.04 Build Log</summary>

```
#0 building with "default" instance using docker driver

#1 [internal] load build definition from ubuntu_24_04.Dockerfile
#1 transferring dockerfile: 8.34kB done
#1 DONE 0.0s

#2 [internal] load metadata for docker.io/library/base-clang:ubuntu_24_04
#2 DONE 0.0s

#3 [internal] load metadata for gcr.io/oss-fuzz-base/indexer:latest
#3 DONE 0.2s

#4 [internal] load .dockerignore
#4 transferring context: 2B done
#4 DONE 0.0s

#5 [stage-0  1/27] FROM docker.io/library/base-clang:ubuntu_24_04
#5 CACHED

#6 [internal] load build context
#6 transferring context: 4.14kB done
#6 DONE 0.0s

#7 [stage-0  2/27] COPY install_deps.sh /
#7 DONE 0.0s

#8 [stage-0 20/27] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc /usr/local/bin/
#8 CACHED

#9 [stage-0 21/27] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc /usr/local/bin
#9 CACHED

#10 [stage-0 22/27] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc2 /usr/local/bin/
#10 CACHED

#11 [stage-0 23/27] ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc2 /usr/local/bin
#11 CACHED

#12 FROM gcr.io/oss-fuzz-base/indexer:latest@sha256:0b3c8d6be91227d926b87fb13971a3385f751e0cc61684136a148aa8d04d48cb
#12 CACHED

#13 [stage-0  3/27] RUN /install_deps.sh && rm /install_deps.sh
#13 0.305 + case $(uname -m) in
#13 0.306 ++ uname -m
#13 0.307 + dpkg --add-architecture i386
#13 0.322 + apt-get update
#13 0.476 Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease
#13 0.480 Hit:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease
#13 0.499 Hit:3 http://archive.ubuntu.com/ubuntu noble-backports InRelease
#13 0.586 Hit:4 http://security.ubuntu.com/ubuntu noble-security InRelease
#13 0.628 Get:5 http://archive.ubuntu.com/ubuntu noble/multiverse i386 Packages [151 kB]
#13 0.724 Get:6 http://archive.ubuntu.com/ubuntu noble/main i386 Packages [1329 kB]
#13 0.794 Get:7 http://archive.ubuntu.com/ubuntu noble/restricted i386 Packages [17.2 kB]
#13 0.794 Get:8 http://archive.ubuntu.com/ubuntu noble/universe i386 Packages [10.3 MB]
#13 0.864 Get:9 http://archive.ubuntu.com/ubuntu noble-updates/universe i386 Packages [1235 kB]
#13 0.870 Get:10 http://archive.ubuntu.com/ubuntu noble-updates/multiverse i386 Packages [8575 B]
#13 0.871 Get:11 http://archive.ubuntu.com/ubuntu noble-updates/restricted i386 Packages [23.5 kB]
#13 0.871 Get:12 http://archive.ubuntu.com/ubuntu noble-updates/main i386 Packages [657 kB]
#13 0.885 Get:13 http://archive.ubuntu.com/ubuntu noble-backports/universe i386 Packages [19.5 kB]
#13 0.886 Get:14 http://archive.ubuntu.com/ubuntu noble-backports/main i386 Packages [39.7 kB]
#13 1.007 Get:15 http://security.ubuntu.com/ubuntu noble-security/main i386 Packages [401 kB]
#13 1.506 Get:16 http://security.ubuntu.com/ubuntu noble-security/multiverse i386 Packages [3897 B]
#13 1.507 Get:17 http://security.ubuntu.com/ubuntu noble-security/restricted i386 Packages [20.7 kB]
#13 1.509 Get:18 http://security.ubuntu.com/ubuntu noble-security/universe i386 Packages [676 kB]
#13 1.679 Fetched 14.9 MB in 1s (11.8 MB/s)
#13 1.679 Reading package lists...
#13 2.677 + apt-get install -y binutils-dev build-essential curl wget git jq patchelf rsync subversion zip
#13 2.693 Reading package lists...
#13 3.695 Building dependency tree...
#13 3.941 Reading state information...
#13 4.148 The following additional packages will be installed:
#13 4.148   bzip2 cpp cpp-13 cpp-13-x86-64-linux-gnu cpp-x86-64-linux-gnu dirmngr
#13 4.148   dpkg-dev fakeroot g++ g++-13 g++-13-x86-64-linux-gnu g++-x86-64-linux-gnu
#13 4.148   gcc gcc-13 gcc-13-x86-64-linux-gnu gcc-x86-64-linux-gnu git-man gnupg
#13 4.148   gnupg-l10n gnupg-utils gpg gpg-agent gpg-wks-client gpgconf gpgsm keyboxd
#13 4.148   krb5-locales less libalgorithm-diff-perl libalgorithm-diff-xs-perl
#13 4.148   libalgorithm-merge-perl libapr1t64 libaprutil1t64 libcbor0.10 libcc1-0
#13 4.148   libcurl3t64-gnutls libcurl4t64 libdpkg-perl libedit2 liberror-perl
#13 4.148   libfakeroot libfido2-1 libfile-fcntllock-perl libgdbm-compat4t64 libgdbm6t64
#13 4.148   libgssapi-krb5-2 libisl23 libjq1 libk5crypto3 libkeyutils1 libkrb5-3
#13 4.148   libkrb5support0 libksba8 libldap-common libldap2 liblocale-gettext-perl
#13 4.148   libmpc3 libmpfr6 libnghttp2-14 libonig5 libperl5.38t64 libpopt0 libpsl5t64
#13 4.149   libreadline8t64 librtmp1 libsasl2-2 libsasl2-modules libsasl2-modules-db
#13 4.149   libserf-1-1 libsqlite3-0 libssh-4 libstdc++-13-dev libsvn1 libutf8proc3
#13 4.149   libxext6 libxmuu1 lto-disabled-list make netbase openssh-client patch perl
#13 4.149   perl-modules-5.38 pinentry-curses publicsuffix readline-common unzip xauth
#13 4.149   xz-utils
#13 4.150 Suggested packages:
#13 4.150   bzip2-doc cpp-doc gcc-13-locales cpp-13-doc dbus-user-session libpam-systemd
#13 4.150   pinentry-gnome3 tor debian-keyring g++-multilib g++-13-multilib gcc-13-doc
#13 4.150   gcc-multilib autoconf automake libtool flex bison gdb gcc-doc
#13 4.150   gcc-13-multilib gdb-x86-64-linux-gnu gettext-base git-daemon-run
#13 4.150   | git-daemon-sysvinit git-doc git-email git-gui gitk gitweb git-cvs
#13 4.150   git-mediawiki git-svn parcimonie xloadimage gpg-wks-server scdaemon bzr
#13 4.150   gdbm-l10n krb5-doc krb5-user libsasl2-modules-gssapi-mit
#13 4.150   | libsasl2-modules-gssapi-heimdal libsasl2-modules-ldap libsasl2-modules-otp
#13 4.150   libsasl2-modules-sql libstdc++-13-doc make-doc keychain libpam-ssh
#13 4.150   monkeysphere ssh-askpass ed diffutils-doc perl-doc libterm-readline-gnu-perl
#13 4.150   | libterm-readline-perl-perl libtap-harness-archive-perl pinentry-doc
#13 4.150   readline-doc openssh-server python3 python3-braceexpand db5.3-util
#13 4.150   libapache2-mod-svn subversion-tools
#13 4.413 The following NEW packages will be installed:
#13 4.413   binutils-dev build-essential bzip2 cpp cpp-13 cpp-13-x86-64-linux-gnu
#13 4.413   cpp-x86-64-linux-gnu curl dirmngr dpkg-dev fakeroot g++ g++-13
#13 4.413   g++-13-x86-64-linux-gnu g++-x86-64-linux-gnu gcc gcc-13
#13 4.413   gcc-13-x86-64-linux-gnu gcc-x86-64-linux-gnu git git-man gnupg gnupg-l10n
#13 4.413   gnupg-utils gpg gpg-agent gpg-wks-client gpgconf gpgsm jq keyboxd
#13 4.413   krb5-locales less libalgorithm-diff-perl libalgorithm-diff-xs-perl
#13 4.413   libalgorithm-merge-perl libapr1t64 libaprutil1t64 libcbor0.10 libcc1-0
#13 4.413   libcurl3t64-gnutls libcurl4t64 libdpkg-perl libedit2 liberror-perl
#13 4.413   libfakeroot libfido2-1 libfile-fcntllock-perl libgdbm-compat4t64 libgdbm6t64
#13 4.413   libgssapi-krb5-2 libisl23 libjq1 libk5crypto3 libkeyutils1 libkrb5-3
#13 4.413   libkrb5support0 libksba8 libldap-common libldap2 liblocale-gettext-perl
#13 4.413   libmpc3 libmpfr6 libnghttp2-14 libonig5 libperl5.38t64 libpopt0 libpsl5t64
#13 4.414   libreadline8t64 librtmp1 libsasl2-2 libsasl2-modules libsasl2-modules-db
#13 4.414   libserf-1-1 libsqlite3-0 libssh-4 libstdc++-13-dev libsvn1 libutf8proc3
#13 4.414   libxext6 libxmuu1 lto-disabled-list make netbase openssh-client patch
#13 4.414   patchelf perl perl-modules-5.38 pinentry-curses publicsuffix readline-common
#13 4.414   rsync subversion unzip wget xauth xz-utils zip
#13 4.644 0 upgraded, 99 newly installed, 0 to remove and 0 not upgraded.
#13 4.644 Need to get 86.0 MB of archives.
#13 4.644 After this operation, 346 MB of additional disk space will be used.
#13 4.644 Get:1 http://archive.ubuntu.com/ubuntu noble/main amd64 liblocale-gettext-perl amd64 1.07-6ubuntu5 [15.8 kB]
#13 4.810 Get:2 http://archive.ubuntu.com/ubuntu noble/main amd64 libpopt0 amd64 1.19+dfsg-1build1 [28.6 kB]
#13 4.865 Get:3 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 rsync amd64 3.2.7-1ubuntu1.2 [436 kB]
#13 5.177 Get:4 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 perl-modules-5.38 all 5.38.2-3.2ubuntu0.2 [3110 kB]
#13 5.420 Get:5 http://archive.ubuntu.com/ubuntu noble/main amd64 libgdbm6t64 amd64 1.23-5.1build1 [34.4 kB]
#13 5.421 Get:6 http://archive.ubuntu.com/ubuntu noble/main amd64 libgdbm-compat4t64 amd64 1.23-5.1build1 [6710 B]
#13 5.422 Get:7 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libperl5.38t64 amd64 5.38.2-3.2ubuntu0.2 [4874 kB]
#13 5.526 Get:8 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 perl amd64 5.38.2-3.2ubuntu0.2 [231 kB]
#13 5.531 Get:9 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 krb5-locales all 1.20.1-6ubuntu2.6 [14.8 kB]
#13 5.531 Get:10 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 less amd64 590-2ubuntu2.1 [142 kB]
#13 5.535 Get:11 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libkrb5support0 amd64 1.20.1-6ubuntu2.6 [34.4 kB]
#13 5.535 Get:12 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libk5crypto3 amd64 1.20.1-6ubuntu2.6 [82.0 kB]
#13 5.538 Get:13 http://archive.ubuntu.com/ubuntu noble/main amd64 libkeyutils1 amd64 1.6.3-3build1 [9490 B]
#13 5.539 Get:14 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libkrb5-3 amd64 1.20.1-6ubuntu2.6 [348 kB]
#13 5.545 Get:15 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libgssapi-krb5-2 amd64 1.20.1-6ubuntu2.6 [143 kB]
#13 5.550 Get:16 http://archive.ubuntu.com/ubuntu noble/main amd64 readline-common all 8.2-4build1 [56.5 kB]
#13 5.610 Get:17 http://archive.ubuntu.com/ubuntu noble/main amd64 libreadline8t64 amd64 8.2-4build1 [153 kB]
#13 5.693 Get:18 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libsqlite3-0 amd64 3.45.1-1ubuntu2.4 [701 kB]
#13 5.699 Get:19 http://archive.ubuntu.com/ubuntu noble/main amd64 netbase all 6.4 [13.1 kB]
#13 5.699 Get:20 http://archive.ubuntu.com/ubuntu noble/main amd64 libcbor0.10 amd64 0.10.2-1.2ubuntu2 [25.8 kB]
#13 5.700 Get:21 http://archive.ubuntu.com/ubuntu noble/main amd64 libedit2 amd64 3.1-20230828-1build1 [97.6 kB]
#13 5.702 Get:22 http://archive.ubuntu.com/ubuntu noble/main amd64 libfido2-1 amd64 1.14.0-1build3 [83.5 kB]
#13 5.703 Get:23 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libnghttp2-14 amd64 1.59.0-1ubuntu0.2 [74.3 kB]
#13 5.704 Get:24 http://archive.ubuntu.com/ubuntu noble/main amd64 libpsl5t64 amd64 0.21.2-1.1build1 [57.1 kB]
#13 5.705 Get:25 http://archive.ubuntu.com/ubuntu noble/main amd64 libxext6 amd64 2:1.3.4-1build2 [30.4 kB]
#13 5.706 Get:26 http://archive.ubuntu.com/ubuntu noble/main amd64 libxmuu1 amd64 2:1.1.3-3build2 [8958 B]
#13 5.776 Get:27 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 openssh-client amd64 1:9.6p1-3ubuntu13.13 [906 kB]
#13 5.858 Get:28 http://archive.ubuntu.com/ubuntu noble/main amd64 publicsuffix all 20231001.0357-0.1 [129 kB]
#13 5.860 Get:29 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 wget amd64 1.21.4-1ubuntu4.1 [334 kB]
#13 5.864 Get:30 http://archive.ubuntu.com/ubuntu noble/main amd64 xauth amd64 1:1.1.2-1build1 [25.6 kB]
#13 5.865 Get:31 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 xz-utils amd64 5.6.1+really5.4.5-1ubuntu0.2 [267 kB]
#13 5.867 Get:32 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libisl23 amd64 0.26-3build1.1 [680 kB]
#13 5.873 Get:33 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libmpfr6 amd64 4.2.1-1build1.1 [353 kB]
#13 5.876 Get:34 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libmpc3 amd64 1.3.1-1build1.1 [54.6 kB]
#13 5.877 Get:35 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 cpp-13-x86-64-linux-gnu amd64 13.3.0-6ubuntu2~24.04 [10.7 MB]
#13 6.113 Get:36 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 cpp-13 amd64 13.3.0-6ubuntu2~24.04 [1038 B]
#13 6.114 Get:37 http://archive.ubuntu.com/ubuntu noble/main amd64 cpp-x86-64-linux-gnu amd64 4:13.2.0-7ubuntu1 [5326 B]
#13 6.115 Get:38 http://archive.ubuntu.com/ubuntu noble/main amd64 cpp amd64 4:13.2.0-7ubuntu1 [22.4 kB]
#13 6.116 Get:39 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libcc1-0 amd64 14.2.0-4ubuntu2~24.04 [48.0 kB]
#13 6.117 Get:40 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gcc-13-x86-64-linux-gnu amd64 13.3.0-6ubuntu2~24.04 [21.1 MB]
#13 6.547 Get:41 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gcc-13 amd64 13.3.0-6ubuntu2~24.04 [494 kB]
#13 6.551 Get:42 http://archive.ubuntu.com/ubuntu noble/main amd64 gcc-x86-64-linux-gnu amd64 4:13.2.0-7ubuntu1 [1212 B]
#13 6.552 Get:43 http://archive.ubuntu.com/ubuntu noble/main amd64 gcc amd64 4:13.2.0-7ubuntu1 [5018 B]
#13 6.553 Get:44 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libstdc++-13-dev amd64 13.3.0-6ubuntu2~24.04 [2420 kB]
#13 6.600 Get:45 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 g++-13-x86-64-linux-gnu amd64 13.3.0-6ubuntu2~24.04 [12.2 MB]
#13 6.844 Get:46 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 g++-13 amd64 13.3.0-6ubuntu2~24.04 [16.1 kB]
#13 6.845 Get:47 http://archive.ubuntu.com/ubuntu noble/main amd64 g++-x86-64-linux-gnu amd64 4:13.2.0-7ubuntu1 [964 B]
#13 6.846 Get:48 http://archive.ubuntu.com/ubuntu noble/main amd64 g++ amd64 4:13.2.0-7ubuntu1 [1100 B]
#13 6.847 Get:49 http://archive.ubuntu.com/ubuntu noble/main amd64 make amd64 4.3-4.1build2 [180 kB]
#13 6.849 Get:50 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libdpkg-perl all 1.22.6ubuntu6.1 [269 kB]
#13 6.852 Get:51 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 bzip2 amd64 1.0.8-5.1build0.1 [34.5 kB]
#13 6.853 Get:52 http://archive.ubuntu.com/ubuntu noble/main amd64 patch amd64 2.7.6-7build3 [104 kB]
#13 6.854 Get:53 http://archive.ubuntu.com/ubuntu noble/main amd64 lto-disabled-list all 47 [12.4 kB]
#13 6.855 Get:54 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 dpkg-dev all 1.22.6ubuntu6.1 [1074 kB]
#13 6.965 Get:55 http://archive.ubuntu.com/ubuntu noble/main amd64 build-essential amd64 12.10ubuntu1 [4928 B]
#13 6.966 Get:56 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libsasl2-modules-db amd64 2.1.28+dfsg1-5ubuntu3.1 [20.4 kB]
#13 6.967 Get:57 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libsasl2-2 amd64 2.1.28+dfsg1-5ubuntu3.1 [53.2 kB]
#13 6.968 Get:58 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libldap2 amd64 2.6.7+dfsg-1~exp1ubuntu8.2 [196 kB]
#13 6.971 Get:59 http://archive.ubuntu.com/ubuntu noble/main amd64 librtmp1 amd64 2.4+20151223.gitfa8646d.1-2build7 [56.3 kB]
#13 6.972 Get:60 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libssh-4 amd64 0.10.6-2ubuntu0.1 [188 kB]
#13 7.045 Get:61 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libcurl4t64 amd64 8.5.0-2ubuntu10.6 [341 kB]
#13 7.051 Get:62 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 curl amd64 8.5.0-2ubuntu10.6 [226 kB]
#13 7.055 Get:63 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gpgconf amd64 2.4.4-2ubuntu17.3 [104 kB]
#13 7.056 Get:64 http://archive.ubuntu.com/ubuntu noble/main amd64 libksba8 amd64 1.6.6-1build1 [122 kB]
#13 7.126 Get:65 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 dirmngr amd64 2.4.4-2ubuntu17.3 [323 kB]
#13 7.131 Get:66 http://archive.ubuntu.com/ubuntu noble/main amd64 libfakeroot amd64 1.33-1 [32.4 kB]
#13 7.132 Get:67 http://archive.ubuntu.com/ubuntu noble/main amd64 fakeroot amd64 1.33-1 [67.2 kB]
#13 7.133 Get:68 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libcurl3t64-gnutls amd64 8.5.0-2ubuntu10.6 [333 kB]
#13 7.138 Get:69 http://archive.ubuntu.com/ubuntu noble/main amd64 liberror-perl all 0.17029-2 [25.6 kB]
#13 7.209 Get:70 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 git-man all 1:2.43.0-1ubuntu7.3 [1100 kB]
#13 7.226 Get:71 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 git amd64 1:2.43.0-1ubuntu7.3 [3680 kB]
#13 7.303 Get:72 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gnupg-utils amd64 2.4.4-2ubuntu17.3 [109 kB]
#13 7.304 Get:73 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gpg amd64 2.4.4-2ubuntu17.3 [565 kB]
#13 7.314 Get:74 http://archive.ubuntu.com/ubuntu noble/main amd64 pinentry-curses amd64 1.2.1-3ubuntu5 [35.2 kB]
#13 7.314 Get:75 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gpg-agent amd64 2.4.4-2ubuntu17.3 [227 kB]
#13 7.317 Get:76 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gpgsm amd64 2.4.4-2ubuntu17.3 [232 kB]
#13 7.321 Get:77 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 keyboxd amd64 2.4.4-2ubuntu17.3 [78.3 kB]
#13 7.322 Get:78 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gnupg all 2.4.4-2ubuntu17.3 [359 kB]
#13 7.329 Get:79 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gnupg-l10n all 2.4.4-2ubuntu17.3 [66.4 kB]
#13 7.375 Get:80 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 gpg-wks-client amd64 2.4.4-2ubuntu17.3 [70.9 kB]
#13 7.414 Get:81 http://archive.ubuntu.com/ubuntu noble/main amd64 libonig5 amd64 6.9.9-1build1 [172 kB]
#13 7.417 Get:82 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libjq1 amd64 1.7.1-3ubuntu0.24.04.1 [141 kB]
#13 7.419 Get:83 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 jq amd64 1.7.1-3ubuntu0.24.04.1 [65.7 kB]
#13 7.420 Get:84 http://archive.ubuntu.com/ubuntu noble/main amd64 libalgorithm-diff-perl all 1.201-1 [41.8 kB]
#13 7.421 Get:85 http://archive.ubuntu.com/ubuntu noble/main amd64 libalgorithm-diff-xs-perl amd64 0.04-8build3 [11.2 kB]
#13 7.458 Get:86 http://archive.ubuntu.com/ubuntu noble/main amd64 libalgorithm-merge-perl all 0.08-5 [11.4 kB]
#13 7.459 Get:87 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libapr1t64 amd64 1.7.2-3.1ubuntu0.1 [108 kB]
#13 7.460 Get:88 http://archive.ubuntu.com/ubuntu noble/main amd64 libaprutil1t64 amd64 1.6.3-1.1ubuntu7 [91.9 kB]
#13 7.461 Get:89 http://archive.ubuntu.com/ubuntu noble/main amd64 libfile-fcntllock-perl amd64 0.22-4ubuntu5 [30.7 kB]
#13 7.540 Get:90 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libldap-common all 2.6.7+dfsg-1~exp1ubuntu8.2 [31.7 kB]
#13 7.541 Get:91 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 libsasl2-modules amd64 2.1.28+dfsg1-5ubuntu3.1 [69.9 kB]
#13 7.542 Get:92 http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 libserf-1-1 amd64 1.3.10-1ubuntu0.24.04.1 [48.2 kB]
#13 7.543 Get:93 http://archive.ubuntu.com/ubuntu noble/universe amd64 libutf8proc3 amd64 2.9.0-1build1 [70.6 kB]
#13 7.544 Get:94 http://archive.ubuntu.com/ubuntu noble/universe amd64 libsvn1 amd64 1.14.3-1build4 [1345 kB]
#13 7.623 Get:95 http://archive.ubuntu.com/ubuntu noble/universe amd64 patchelf amd64 0.18.0-1.1build1 [106 kB]
#13 7.625 Get:96 http://archive.ubuntu.com/ubuntu noble/universe amd64 subversion amd64 1.14.3-1build4 [908 kB]
#13 7.639 Get:97 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 unzip amd64 6.0-28ubuntu4.1 [174 kB]
#13 7.642 Get:98 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 zip amd64 3.0-13ubuntu0.2 [176 kB]
#13 7.645 Get:99 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 binutils-dev amd64 2.42-4ubuntu2.5 [11.5 MB]
#13 8.050 debconf: delaying package configuration, since apt-utils is not installed
#13 8.100 Fetched 86.0 MB in 3s (25.1 MB/s)
#13 8.137 Selecting previously unselected package liblocale-gettext-perl.
#13 8.137 (Reading database ... (Reading database ... 5%(Reading database ... 10%(Reading database ... 15%(Reading database ... 20%(Reading database ... 25%(Reading database ... 30%(Reading database ... 35%(Reading database ... 40%(Reading database ... 45%(Reading database ... 50%(Reading database ... 55%(Reading database ... 60%(Reading database ... 65%(Reading database ... 70%(Reading database ... 75%(Reading database ... 80%(Reading database ... 85%(Reading database ... 90%(Reading database ... 95%(Reading database ... 100%(Reading database ... 10782 files and directories currently installed.)
#13 8.171 Preparing to unpack .../00-liblocale-gettext-perl_1.07-6ubuntu5_amd64.deb ...
#13 8.175 Unpacking liblocale-gettext-perl (1.07-6ubuntu5) ...
#13 8.238 Selecting previously unselected package libpopt0:amd64.
#13 8.240 Preparing to unpack .../01-libpopt0_1.19+dfsg-1build1_amd64.deb ...
#13 8.248 Unpacking libpopt0:amd64 (1.19+dfsg-1build1) ...
#13 8.302 Selecting previously unselected package rsync.
#13 8.304 Preparing to unpack .../02-rsync_3.2.7-1ubuntu1.2_amd64.deb ...
#13 8.310 Unpacking rsync (3.2.7-1ubuntu1.2) ...
#13 8.401 Selecting previously unselected package perl-modules-5.38.
#13 8.403 Preparing to unpack .../03-perl-modules-5.38_5.38.2-3.2ubuntu0.2_all.deb ...
#13 8.407 Unpacking perl-modules-5.38 (5.38.2-3.2ubuntu0.2) ...
#13 9.657 Selecting previously unselected package libgdbm6t64:amd64.
#13 9.659 Preparing to unpack .../04-libgdbm6t64_1.23-5.1build1_amd64.deb ...
#13 9.663 Unpacking libgdbm6t64:amd64 (1.23-5.1build1) ...
#13 9.713 Selecting previously unselected package libgdbm-compat4t64:amd64.
#13 9.714 Preparing to unpack .../05-libgdbm-compat4t64_1.23-5.1build1_amd64.deb ...
#13 9.718 Unpacking libgdbm-compat4t64:amd64 (1.23-5.1build1) ...
#13 9.766 Selecting previously unselected package libperl5.38t64:amd64.
#13 9.768 Preparing to unpack .../06-libperl5.38t64_5.38.2-3.2ubuntu0.2_amd64.deb ...
#13 9.772 Unpacking libperl5.38t64:amd64 (5.38.2-3.2ubuntu0.2) ...
#13 10.34 Selecting previously unselected package perl.
#13 10.35 Preparing to unpack .../07-perl_5.38.2-3.2ubuntu0.2_amd64.deb ...
#13 10.36 Unpacking perl (5.38.2-3.2ubuntu0.2) ...
#13 10.44 Selecting previously unselected package krb5-locales.
#13 10.44 Preparing to unpack .../08-krb5-locales_1.20.1-6ubuntu2.6_all.deb ...
#13 10.45 Unpacking krb5-locales (1.20.1-6ubuntu2.6) ...
#13 10.49 Selecting previously unselected package less.
#13 10.49 Preparing to unpack .../09-less_590-2ubuntu2.1_amd64.deb ...
#13 10.50 Unpacking less (590-2ubuntu2.1) ...
#13 10.55 Selecting previously unselected package libkrb5support0:amd64.
#13 10.55 Preparing to unpack .../10-libkrb5support0_1.20.1-6ubuntu2.6_amd64.deb ...
#13 10.56 Unpacking libkrb5support0:amd64 (1.20.1-6ubuntu2.6) ...
#13 10.61 Selecting previously unselected package libk5crypto3:amd64.
#13 10.61 Preparing to unpack .../11-libk5crypto3_1.20.1-6ubuntu2.6_amd64.deb ...
#13 10.61 Unpacking libk5crypto3:amd64 (1.20.1-6ubuntu2.6) ...
#13 10.66 Selecting previously unselected package libkeyutils1:amd64.
#13 10.66 Preparing to unpack .../12-libkeyutils1_1.6.3-3build1_amd64.deb ...
#13 10.66 Unpacking libkeyutils1:amd64 (1.6.3-3build1) ...
#13 10.71 Selecting previously unselected package libkrb5-3:amd64.
#13 10.71 Preparing to unpack .../13-libkrb5-3_1.20.1-6ubuntu2.6_amd64.deb ...
#13 10.71 Unpacking libkrb5-3:amd64 (1.20.1-6ubuntu2.6) ...
#13 10.77 Selecting previously unselected package libgssapi-krb5-2:amd64.
#13 10.77 Preparing to unpack .../14-libgssapi-krb5-2_1.20.1-6ubuntu2.6_amd64.deb ...
#13 10.78 Unpacking libgssapi-krb5-2:amd64 (1.20.1-6ubuntu2.6) ...
#13 10.83 Selecting previously unselected package readline-common.
#13 10.83 Preparing to unpack .../15-readline-common_8.2-4build1_all.deb ...
#13 10.83 Unpacking readline-common (8.2-4build1) ...
#13 10.88 Selecting previously unselected package libreadline8t64:amd64.
#13 10.89 Preparing to unpack .../16-libreadline8t64_8.2-4build1_amd64.deb ...
#13 10.90 Adding 'diversion of /lib/x86_64-linux-gnu/libhistory.so.8 to /lib/x86_64-linux-gnu/libhistory.so.8.usr-is-merged by libreadline8t64'
#13 10.91 Adding 'diversion of /lib/x86_64-linux-gnu/libhistory.so.8.2 to /lib/x86_64-linux-gnu/libhistory.so.8.2.usr-is-merged by libreadline8t64'
#13 10.93 Adding 'diversion of /lib/x86_64-linux-gnu/libreadline.so.8 to /lib/x86_64-linux-gnu/libreadline.so.8.usr-is-merged by libreadline8t64'
#13 10.94 Adding 'diversion of /lib/x86_64-linux-gnu/libreadline.so.8.2 to /lib/x86_64-linux-gnu/libreadline.so.8.2.usr-is-merged by libreadline8t64'
#13 10.94 Unpacking libreadline8t64:amd64 (8.2-4build1) ...
#13 10.99 Selecting previously unselected package libsqlite3-0:amd64.
#13 11.00 Preparing to unpack .../17-libsqlite3-0_3.45.1-1ubuntu2.4_amd64.deb ...
#13 11.00 Unpacking libsqlite3-0:amd64 (3.45.1-1ubuntu2.4) ...
#13 11.05 Selecting previously unselected package netbase.
#13 11.05 Preparing to unpack .../18-netbase_6.4_all.deb ...
#13 11.06 Unpacking netbase (6.4) ...
#13 11.10 Selecting previously unselected package libcbor0.10:amd64.
#13 11.10 Preparing to unpack .../19-libcbor0.10_0.10.2-1.2ubuntu2_amd64.deb ...
#13 11.11 Unpacking libcbor0.10:amd64 (0.10.2-1.2ubuntu2) ...
#13 11.16 Selecting previously unselected package libedit2:amd64.
#13 11.16 Preparing to unpack .../20-libedit2_3.1-20230828-1build1_amd64.deb ...
#13 11.16 Unpacking libedit2:amd64 (3.1-20230828-1build1) ...
#13 11.21 Selecting previously unselected package libfido2-1:amd64.
#13 11.22 Preparing to unpack .../21-libfido2-1_1.14.0-1build3_amd64.deb ...
#13 11.22 Unpacking libfido2-1:amd64 (1.14.0-1build3) ...
#13 11.27 Selecting previously unselected package libnghttp2-14:amd64.
#13 11.27 Preparing to unpack .../22-libnghttp2-14_1.59.0-1ubuntu0.2_amd64.deb ...
#13 11.27 Unpacking libnghttp2-14:amd64 (1.59.0-1ubuntu0.2) ...
#13 11.32 Selecting previously unselected package libpsl5t64:amd64.
#13 11.32 Preparing to unpack .../23-libpsl5t64_0.21.2-1.1build1_amd64.deb ...
#13 11.33 Unpacking libpsl5t64:amd64 (0.21.2-1.1build1) ...
#13 11.38 Selecting previously unselected package libxext6:amd64.
#13 11.38 Preparing to unpack .../24-libxext6_2%3a1.3.4-1build2_amd64.deb ...
#13 11.38 Unpacking libxext6:amd64 (2:1.3.4-1build2) ...
#13 11.43 Selecting previously unselected package libxmuu1:amd64.
#13 11.43 Preparing to unpack .../25-libxmuu1_2%3a1.1.3-3build2_amd64.deb ...
#13 11.43 Unpacking libxmuu1:amd64 (2:1.1.3-3build2) ...
#13 11.48 Selecting previously unselected package openssh-client.
#13 11.48 Preparing to unpack .../26-openssh-client_1%3a9.6p1-3ubuntu13.13_amd64.deb ...
#13 11.50 Unpacking openssh-client (1:9.6p1-3ubuntu13.13) ...
#13 11.58 Selecting previously unselected package publicsuffix.
#13 11.58 Preparing to unpack .../27-publicsuffix_20231001.0357-0.1_all.deb ...
#13 11.59 Unpacking publicsuffix (20231001.0357-0.1) ...
#13 11.63 Selecting previously unselected package wget.
#13 11.63 Preparing to unpack .../28-wget_1.21.4-1ubuntu4.1_amd64.deb ...
#13 11.64 Unpacking wget (1.21.4-1ubuntu4.1) ...
#13 11.68 Selecting previously unselected package xauth.
#13 11.69 Preparing to unpack .../29-xauth_1%3a1.1.2-1build1_amd64.deb ...
#13 11.69 Unpacking xauth (1:1.1.2-1build1) ...
#13 11.73 Selecting previously unselected package xz-utils.
#13 11.73 Preparing to unpack .../30-xz-utils_5.6.1+really5.4.5-1ubuntu0.2_amd64.deb ...
#13 11.74 Unpacking xz-utils (5.6.1+really5.4.5-1ubuntu0.2) ...
#13 11.82 Selecting previously unselected package libisl23:amd64.
#13 11.82 Preparing to unpack .../31-libisl23_0.26-3build1.1_amd64.deb ...
#13 11.83 Unpacking libisl23:amd64 (0.26-3build1.1) ...
#13 11.89 Selecting previously unselected package libmpfr6:amd64.
#13 11.89 Preparing to unpack .../32-libmpfr6_4.2.1-1build1.1_amd64.deb ...
#13 11.90 Unpacking libmpfr6:amd64 (4.2.1-1build1.1) ...
#13 11.95 Selecting previously unselected package libmpc3:amd64.
#13 11.95 Preparing to unpack .../33-libmpc3_1.3.1-1build1.1_amd64.deb ...
#13 11.96 Unpacking libmpc3:amd64 (1.3.1-1build1.1) ...
#13 12.00 Selecting previously unselected package cpp-13-x86-64-linux-gnu.
#13 12.00 Preparing to unpack .../34-cpp-13-x86-64-linux-gnu_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 12.00 Unpacking cpp-13-x86-64-linux-gnu (13.3.0-6ubuntu2~24.04) ...
#13 12.18 Selecting previously unselected package cpp-13.
#13 12.18 Preparing to unpack .../35-cpp-13_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 12.19 Unpacking cpp-13 (13.3.0-6ubuntu2~24.04) ...
#13 12.22 Selecting previously unselected package cpp-x86-64-linux-gnu.
#13 12.23 Preparing to unpack .../36-cpp-x86-64-linux-gnu_4%3a13.2.0-7ubuntu1_amd64.deb ...
#13 12.23 Unpacking cpp-x86-64-linux-gnu (4:13.2.0-7ubuntu1) ...
#13 12.28 Selecting previously unselected package cpp.
#13 12.28 Preparing to unpack .../37-cpp_4%3a13.2.0-7ubuntu1_amd64.deb ...
#13 12.29 Unpacking cpp (4:13.2.0-7ubuntu1) ...
#13 12.35 Selecting previously unselected package libcc1-0:amd64.
#13 12.35 Preparing to unpack .../38-libcc1-0_14.2.0-4ubuntu2~24.04_amd64.deb ...
#13 12.35 Unpacking libcc1-0:amd64 (14.2.0-4ubuntu2~24.04) ...
#13 12.40 Selecting previously unselected package gcc-13-x86-64-linux-gnu.
#13 12.40 Preparing to unpack .../39-gcc-13-x86-64-linux-gnu_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 12.40 Unpacking gcc-13-x86-64-linux-gnu (13.3.0-6ubuntu2~24.04) ...
#13 12.77 Selecting previously unselected package gcc-13.
#13 12.77 Preparing to unpack .../40-gcc-13_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 12.77 Unpacking gcc-13 (13.3.0-6ubuntu2~24.04) ...
#13 12.83 Selecting previously unselected package gcc-x86-64-linux-gnu.
#13 12.83 Preparing to unpack .../41-gcc-x86-64-linux-gnu_4%3a13.2.0-7ubuntu1_amd64.deb ...
#13 12.83 Unpacking gcc-x86-64-linux-gnu (4:13.2.0-7ubuntu1) ...
#13 12.88 Selecting previously unselected package gcc.
#13 12.88 Preparing to unpack .../42-gcc_4%3a13.2.0-7ubuntu1_amd64.deb ...
#13 12.88 Unpacking gcc (4:13.2.0-7ubuntu1) ...
#13 12.93 Selecting previously unselected package libstdc++-13-dev:amd64.
#13 12.93 Preparing to unpack .../43-libstdc++-13-dev_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 12.94 Unpacking libstdc++-13-dev:amd64 (13.3.0-6ubuntu2~24.04) ...
#13 13.77 Selecting previously unselected package g++-13-x86-64-linux-gnu.
#13 13.77 Preparing to unpack .../44-g++-13-x86-64-linux-gnu_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 13.78 Unpacking g++-13-x86-64-linux-gnu (13.3.0-6ubuntu2~24.04) ...
#13 13.99 Selecting previously unselected package g++-13.
#13 13.99 Preparing to unpack .../45-g++-13_13.3.0-6ubuntu2~24.04_amd64.deb ...
#13 13.99 Unpacking g++-13 (13.3.0-6ubuntu2~24.04) ...
#13 14.03 Selecting previously unselected package g++-x86-64-linux-gnu.
#13 14.03 Preparing to unpack .../46-g++-x86-64-linux-gnu_4%3a13.2.0-7ubuntu1_amd64.deb ...
#13 14.04 Unpacking g++-x86-64-linux-gnu (4:13.2.0-7ubuntu1) ...
#13 14.07 Selecting previously unselected package g++.
#13 14.08 Preparing to unpack .../47-g++_4%3a13.2.0-7ubuntu1_amd64.deb ...
#13 14.08 Unpacking g++ (4:13.2.0-7ubuntu1) ...
#13 14.12 Selecting previously unselected package make.
#13 14.12 Preparing to unpack .../48-make_4.3-4.1build2_amd64.deb ...
#13 14.12 Unpacking make (4.3-4.1build2) ...
#13 14.17 Selecting previously unselected package libdpkg-perl.
#13 14.17 Preparing to unpack .../49-libdpkg-perl_1.22.6ubuntu6.1_all.deb ...
#13 14.17 Unpacking libdpkg-perl (1.22.6ubuntu6.1) ...
#13 14.33 Selecting previously unselected package bzip2.
#13 14.33 Preparing to unpack .../50-bzip2_1.0.8-5.1build0.1_amd64.deb ...
#13 14.34 Unpacking bzip2 (1.0.8-5.1build0.1) ...
#13 14.39 Selecting previously unselected package patch.
#13 14.39 Preparing to unpack .../51-patch_2.7.6-7build3_amd64.deb ...
#13 14.39 Unpacking patch (2.7.6-7build3) ...
#13 14.43 Selecting previously unselected package lto-disabled-list.
#13 14.44 Preparing to unpack .../52-lto-disabled-list_47_all.deb ...
#13 14.44 Unpacking lto-disabled-list (47) ...
#13 14.48 Selecting previously unselected package dpkg-dev.
#13 14.48 Preparing to unpack .../53-dpkg-dev_1.22.6ubuntu6.1_all.deb ...
#13 14.49 Unpacking dpkg-dev (1.22.6ubuntu6.1) ...
#13 14.62 Selecting previously unselected package build-essential.
#13 14.63 Preparing to unpack .../54-build-essential_12.10ubuntu1_amd64.deb ...
#13 14.63 Unpacking build-essential (12.10ubuntu1) ...
#13 14.67 Selecting previously unselected package libsasl2-modules-db:amd64.
#13 14.67 Preparing to unpack .../55-libsasl2-modules-db_2.1.28+dfsg1-5ubuntu3.1_amd64.deb ...
#13 14.68 Unpacking libsasl2-modules-db:amd64 (2.1.28+dfsg1-5ubuntu3.1) ...
#13 14.72 Selecting previously unselected package libsasl2-2:amd64.
#13 14.72 Preparing to unpack .../56-libsasl2-2_2.1.28+dfsg1-5ubuntu3.1_amd64.deb ...
#13 14.73 Unpacking libsasl2-2:amd64 (2.1.28+dfsg1-5ubuntu3.1) ...
#13 14.78 Selecting previously unselected package libldap2:amd64.
#13 14.78 Preparing to unpack .../57-libldap2_2.6.7+dfsg-1~exp1ubuntu8.2_amd64.deb ...
#13 14.78 Unpacking libldap2:amd64 (2.6.7+dfsg-1~exp1ubuntu8.2) ...
#13 14.83 Selecting previously unselected package librtmp1:amd64.
#13 14.83 Preparing to unpack .../58-librtmp1_2.4+20151223.gitfa8646d.1-2build7_amd64.deb ...
#13 14.84 Unpacking librtmp1:amd64 (2.4+20151223.gitfa8646d.1-2build7) ...
#13 14.88 Selecting previously unselected package libssh-4:amd64.
#13 14.89 Preparing to unpack .../59-libssh-4_0.10.6-2ubuntu0.1_amd64.deb ...
#13 14.89 Unpacking libssh-4:amd64 (0.10.6-2ubuntu0.1) ...
#13 14.94 Selecting previously unselected package libcurl4t64:amd64.
#13 14.94 Preparing to unpack .../60-libcurl4t64_8.5.0-2ubuntu10.6_amd64.deb ...
#13 14.95 Unpacking libcurl4t64:amd64 (8.5.0-2ubuntu10.6) ...
#13 14.99 Selecting previously unselected package curl.
#13 14.99 Preparing to unpack .../61-curl_8.5.0-2ubuntu10.6_amd64.deb ...
#13 15.00 Unpacking curl (8.5.0-2ubuntu10.6) ...
#13 15.04 Selecting previously unselected package gpgconf.
#13 15.04 Preparing to unpack .../62-gpgconf_2.4.4-2ubuntu17.3_amd64.deb ...
#13 15.05 Unpacking gpgconf (2.4.4-2ubuntu17.3) ...
#13 15.10 Selecting previously unselected package libksba8:amd64.
#13 15.10 Preparing to unpack .../63-libksba8_1.6.6-1build1_amd64.deb ...
#13 15.10 Unpacking libksba8:amd64 (1.6.6-1build1) ...
#13 15.15 Selecting previously unselected package dirmngr.
#13 15.15 Preparing to unpack .../64-dirmngr_2.4.4-2ubuntu17.3_amd64.deb ...
#13 15.18 Unpacking dirmngr (2.4.4-2ubuntu17.3) ...
#13 15.23 Selecting previously unselected package libfakeroot:amd64.
#13 15.23 Preparing to unpack .../65-libfakeroot_1.33-1_amd64.deb ...
#13 15.24 Unpacking libfakeroot:amd64 (1.33-1) ...
#13 15.29 Selecting previously unselected package fakeroot.
#13 15.29 Preparing to unpack .../66-fakeroot_1.33-1_amd64.deb ...
#13 15.29 Unpacking fakeroot (1.33-1) ...
#13 15.36 Selecting previously unselected package libcurl3t64-gnutls:amd64.
#13 15.36 Preparing to unpack .../67-libcurl3t64-gnutls_8.5.0-2ubuntu10.6_amd64.deb ...
#13 15.37 Unpacking libcurl3t64-gnutls:amd64 (8.5.0-2ubuntu10.6) ...
#13 15.41 Selecting previously unselected package liberror-perl.
#13 15.42 Preparing to unpack .../68-liberror-perl_0.17029-2_all.deb ...
#13 15.42 Unpacking liberror-perl (0.17029-2) ...
#13 15.46 Selecting previously unselected package git-man.
#13 15.47 Preparing to unpack .../69-git-man_1%3a2.43.0-1ubuntu7.3_all.deb ...
#13 15.47 Unpacking git-man (1:2.43.0-1ubuntu7.3) ...
#13 15.56 Selecting previously unselected package git.
#13 15.56 Preparing to unpack .../70-git_1%3a2.43.0-1ubuntu7.3_amd64.deb ...
#13 15.57 Unpacking git (1:2.43.0-1ubuntu7.3) ...
#13 16.00 Selecting previously unselected package gnupg-utils.
#13 16.01 Preparing to unpack .../71-gnupg-utils_2.4.4-2ubuntu17.3_amd64.deb ...
#13 16.01 Unpacking gnupg-utils (2.4.4-2ubuntu17.3) ...
#13 16.06 Selecting previously unselected package gpg.
#13 16.06 Preparing to unpack .../72-gpg_2.4.4-2ubuntu17.3_amd64.deb ...
#13 16.07 Unpacking gpg (2.4.4-2ubuntu17.3) ...
#13 16.11 Selecting previously unselected package pinentry-curses.
#13 16.11 Preparing to unpack .../73-pinentry-curses_1.2.1-3ubuntu5_amd64.deb ...
#13 16.12 Unpacking pinentry-curses (1.2.1-3ubuntu5) ...
#13 16.16 Selecting previously unselected package gpg-agent.
#13 16.17 Preparing to unpack .../74-gpg-agent_2.4.4-2ubuntu17.3_amd64.deb ...
#13 16.17 Unpacking gpg-agent (2.4.4-2ubuntu17.3) ...
#13 16.23 Selecting previously unselected package gpgsm.
#13 16.23 Preparing to unpack .../75-gpgsm_2.4.4-2ubuntu17.3_amd64.deb ...
#13 16.24 Unpacking gpgsm (2.4.4-2ubuntu17.3) ...
#13 16.28 Selecting previously unselected package keyboxd.
#13 16.28 Preparing to unpack .../76-keyboxd_2.4.4-2ubuntu17.3_amd64.deb ...
#13 16.29 Unpacking keyboxd (2.4.4-2ubuntu17.3) ...
#13 16.34 Selecting previously unselected package gnupg.
#13 16.34 Preparing to unpack .../77-gnupg_2.4.4-2ubuntu17.3_all.deb ...
#13 16.34 Unpacking gnupg (2.4.4-2ubuntu17.3) ...
#13 16.40 Selecting previously unselected package gnupg-l10n.
#13 16.40 Preparing to unpack .../78-gnupg-l10n_2.4.4-2ubuntu17.3_all.deb ...
#13 16.40 Unpacking gnupg-l10n (2.4.4-2ubuntu17.3) ...
#13 16.46 Selecting previously unselected package gpg-wks-client.
#13 16.47 Preparing to unpack .../79-gpg-wks-client_2.4.4-2ubuntu17.3_amd64.deb ...
#13 16.47 Unpacking gpg-wks-client (2.4.4-2ubuntu17.3) ...
#13 16.51 Selecting previously unselected package libonig5:amd64.
#13 16.52 Preparing to unpack .../80-libonig5_6.9.9-1build1_amd64.deb ...
#13 16.52 Unpacking libonig5:amd64 (6.9.9-1build1) ...
#13 16.57 Selecting previously unselected package libjq1:amd64.
#13 16.57 Preparing to unpack .../81-libjq1_1.7.1-3ubuntu0.24.04.1_amd64.deb ...
#13 16.57 Unpacking libjq1:amd64 (1.7.1-3ubuntu0.24.04.1) ...
#13 16.61 Selecting previously unselected package jq.
#13 16.62 Preparing to unpack .../82-jq_1.7.1-3ubuntu0.24.04.1_amd64.deb ...
#13 16.62 Unpacking jq (1.7.1-3ubuntu0.24.04.1) ...
#13 16.66 Selecting previously unselected package libalgorithm-diff-perl.
#13 16.66 Preparing to unpack .../83-libalgorithm-diff-perl_1.201-1_all.deb ...
#13 16.69 Unpacking libalgorithm-diff-perl (1.201-1) ...
#13 16.73 Selecting previously unselected package libalgorithm-diff-xs-perl:amd64.
#13 16.73 Preparing to unpack .../84-libalgorithm-diff-xs-perl_0.04-8build3_amd64.deb ...
#13 16.74 Unpacking libalgorithm-diff-xs-perl:amd64 (0.04-8build3) ...
#13 16.78 Selecting previously unselected package libalgorithm-merge-perl.
#13 16.78 Preparing to unpack .../85-libalgorithm-merge-perl_0.08-5_all.deb ...
#13 16.79 Unpacking libalgorithm-merge-perl (0.08-5) ...
#13 16.83 Selecting previously unselected package libapr1t64:amd64.

```

</details>