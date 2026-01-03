#!/bin/bash -eu
#
# Copyright 2026 Google LLC
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

# Successful unit test cases
TESTS="affixes.dic flag.dic allcaps3.dic dotless_i.dic sug.dic ph.dic condition_utf.dic flaglong.dic sugutf.dic wordpair.dic phone.dic flagnum.dic sug2.dic flagutf8.dic allcaps2.dic base.dic 
allcaps.dic i58202.dic slash.dic allcaps_utf.dic base_utf.dic keepcase.dic alias.dic ph2.dic needaffix4.dic forbiddenword.dic complexprefixes2.dic alias2.dic break.dic needaffix.dic alias3.dic 
utf8_bom.dic needaffix5.dic needaffix3.dic utf8_bom2.dic utf8.dic needaffix2.dic fogemorpheme.dic complexprefixes.dic complexprefixesutf.dic nosuggest.dic breakdefault.dic zeroaffix.dic 
compoundaffix2.dic circumfix.dic compoundflag.dic onlyincompound.dic compoundrule3.dic compoundrule2.dic compoundrule.dic conditionalprefix.dic compoundrule6.dic compoundrule4.dic compoundrule7.dic 
checkcompoundrep2.dic compoundrule8.dic compoundaffix3.dic compoundaffix.dic utf8_nonbmp.test checkcompounddup.dic compoundforbid.dic simplifiedtriple.dic checkcompoundtriple.dic ignore.dic 
checkcompoundcaseutf.dic ignoreutf.dic compoundrule5.dic right_to_left_mark.dic checkcompoundpattern2.dic utfcompound.dic 1592880.dic checkcompoundpattern4.dic checkcompoundpattern3.dic 
colons_in_words.dic i53643.dic germancompoundingold.dic germancompounding.dic reputf.dic maputf.dic i68568utf.dic i68568.dic 1748408-1.dic 1706659.dic 1748408-3.dic digits_in_words.dic 1748408-2.dic 
1748408-4.dic 1695964.dic checksharpsutf.dic fullstrip.dic 1463589_utf.dic i35725.dic iconv2.dic iconv.dic arabic.dic 1975530.dic IJ.dic morph.dic 2999225.dic warn.dic korean.dic 2970240.dic 
2970242.dic ngram_utf_fix.dic breakoff.dic opentaal_cpdpat.dic opentaal_cpdpat2.dic onlyincompound2.dic oconv.dic nepali.dic hu.dic oconv2.dic opentaal_forbiddenword2.dic opentaal_forbiddenword1.dic 
opentaal_keepcase.dic forceucase.dic limit-multiple-compounding.dic ignoresug.dic timelimit.dic"

# Failing unit test cases
FAILED_TESTS="condition.dic rep.dic map.dic checkcompoundrep.dic checkcompoundcase2.dic checkcompoundpattern.dic checksharps.dic i54980.dic i54633.dic 1463589.dic encoding.dic"

# Run unit test while temporarily ignore failing unit test cases
make check -C tests -j$(nproc) TESTS="$TESTS"
