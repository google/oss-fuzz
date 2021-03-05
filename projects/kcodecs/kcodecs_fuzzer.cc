/*
# Copyright 2019 Google Inc.
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
#
################################################################################
*/

/*
  Usage:
    python infra/helper.py build_image kcodecs
    python infra/helper.py build_fuzzers --sanitizer undefined|address|memory kcodecs
    python infra/helper.py run_fuzzer kcodecs kcodecs_fuzzer
*/


#include <QCoreApplication>
#include <QVector>

#include "JapaneseGroupProber.h"
#include "nsBig5Prober.h"
#include "nsEUCJPProber.h"
#include "nsGB2312Prober.h"
#include "nsLatin1Prober.h"
#include "nsSBCSGroupProber.h"
#include "nsUniversalDetector.h"
#include "ChineseGroupProber.h"
#include "nsEscCharsetProber.h"
#include "nsEUCKRProber.h"
#include "nsMBCSGroupProber.h"
#include "nsSJISProber.h"
#include "UnicodeGroupProber.h"
#include "kcodecs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int argc = 0;
    QCoreApplication a(argc, nullptr);

    const QVector<kencodingprober::nsCharSetProber*> probers = {
        new kencodingprober::JapaneseGroupProber(),
        new kencodingprober::nsBig5Prober(),
        new kencodingprober::nsEUCJPProber(),
        new kencodingprober::nsGB18030Prober(),
        new kencodingprober::nsLatin1Prober(),
        new kencodingprober::nsSBCSGroupProber(),
        new kencodingprober::nsUniversalDetector(),
        new kencodingprober::ChineseGroupProber(),
        new kencodingprober::nsEscCharSetProber(),
        new kencodingprober::nsEUCKRProber(),
        new kencodingprober::nsMBCSGroupProber(),
        new kencodingprober::nsSJISProber(),
        new kencodingprober::UnicodeGroupProber()
    };

    for (kencodingprober::nsCharSetProber *p : probers) {
        p->HandleData((const char*)data, size);
    }

    qDeleteAll(probers);

    const QByteArray ba((const char *)data, size);
    const QVector<const char*> codecs = { "base64", "quoted-printable", "b", "q", "x-kmime-rfc2231", "x-uuencode" };
    for (const char *codecName : codecs) {
        KCodecs::Codec *c = KCodecs::Codec::codecForName(codecName);
        c->encode(ba, KCodecs::Codec::NewlineCRLF);
        c->decode(ba, KCodecs::Codec::NewlineCRLF);
        c->encode(ba, KCodecs::Codec::NewlineLF);
        c->decode(ba, KCodecs::Codec::NewlineLF);
    }

    return 0;
}
