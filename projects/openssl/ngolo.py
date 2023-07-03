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

import os
import subprocess
import sys

target_header = '''
#include <string.h>
#include <openssl/e_os2.h>
#include <openssl/cms.h>
#include <openssl/crmf.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "internal/nelem.h"
#include "fuzzer.h"


int FuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int FuzzerTestOneInput(const uint8_t* data, size_t size){
    const unsigned char *derp = data;
'''

target_trailer = '''
    return 0;
}

void FuzzerCleanup(void)
{
}
'''

def process_fun(funp, asntypes, owning):
    namesargs = funp.split('(')
    # do not support STACK_OF(
    if len(namesargs) == 2:
        namefun = namesargs[0].split()[1]
        owned = namefun in owning
        args = []
        for arg in namesargs[1].split(","):
            argtype = arg.split()[0]
            if argtype == "const":
                argtype = arg.split()[1]
            if arg.split()[-1].startswith("**"):
                # not supporting pass argument for writing
                return
            if argtype not in asntypes:
                # not supporting not-asn1 argument
                return
            args.append(argtype)

        # we can have a fuzzer, let's write it
        f2 = open("fuzz/%s.c" % namefun, "w")
        f2.write(target_header)
        for i in range(len(args)):
            f2.write("    %s *a%d = NULL;\n" % (args[i], i))

        # parse ASN1
        for i in range(len(args)):
            f2.write("    a%d = d2i_%s(NULL, &derp, size - (derp - data));\n" % (i, args[i]))
            f2.write("    if (a%d == NULL)\n" % i)
            f2.write("        goto end;\n")

        # call function
        if owned:
            f2.write("    if (%s(" % namefun)
        else:
            f2.write("    %s(" % namefun)
        for i in range(len(args)):
            if i > 0:
                f2.write(",")
            f2.write("a%d" % i)
        if owned:
            f2.write(")) {\n")
            f2.write("        a%d = NULL;\n" % (len(args) - 1))
            f2.write("    }\n")
        else:
            f2.write(");\n")

        f2.write("end:\n")
        for i in range(len(args)):
            f2.write("    if (a%d != NULL)\n" % i)
            f2.write("        %s_free(a%d);\n" % (args[i], i))
        f2.write(target_trailer)
        f2.close()

        # and now compile it
        ret = subprocess.run([os.environ.get("CC")] + os.environ.get("CFLAGS").split() + ["-c", "fuzz/%s.c" % namefun, "-o", "fuzz/%s.o" % namefun, "-I", "include"])
        if ret.returncode != 0:
            print("failed")
        ret = subprocess.run([os.environ.get("CXX")] + os.environ.get("CXXFLAGS") + [os.environ.get("LIB_FUZZING_ENGINE"), "fuzz/%s.o" % namefun, "-o", "fuzz_ng_%s" % namefun, "fuzz/driver.o", "libcrypto.a"])
        print(namefun, args)

# first list all asn1 types
asntypes = {}
ret = subprocess.run(["git", "grep", "DECLARE_ASN1_FUNCTIONS(", "include"], capture_output=True, text=True)
for l in ret.stdout.split("\n"):
    fc = l.split(":")
    if len(fc) > 1 and fc[1].startswith("DECLARE_ASN1_FUNCTIONS("):
        asntypes[fc[1][len("DECLARE_ASN1_FUNCTIONS("):-1]] = True

# read a h.in file for function prototypes
funstart = False
funproto = ""
f = open(sys.argv[1], "r")
owningFunctions = ["OSSL_CRMF_MSG_push0_extension", "OSSL_CRMF_MSG_set0_validity", "PKCS7_add0_attrib_signing_time"]
for l in f.readlines():
    # restrict to function prototypes returning int
    if l.startswith("int "):
        funproto = ""
        funstart = True
    if funstart:
        funproto = funproto + l[:-1].lstrip()
        if ");" in l:
            process_fun(funproto, asntypes, owningFunctions)
            funstart = False
