/* Copyright 2024 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// The ideal place for this fuzz target is the boost repository.
#include <boost/regex.hpp>
#ifdef DEBUG
#include <iostream>
#endif
#include <sstream>
#include <string>
#include <iterator>
#include <fuzzer/FuzzedDataProvider.h>

// purpose of the fuzzer:
// fuzz the format string syntax used in match-replace
//
// the mutator comes from a boost example that:
// takes the contents of a file and transform to
// syntax highlighted code in html format

boost::regex e1, e2;
extern const char* expression_text;
extern const char* pre_expression;
extern const char* pre_format;
extern const char* match_against;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
    FuzzedDataProvider fdp(Data, Size);
    std::string format_string = fdp.ConsumeRemainingBytesAsString();
    try{
        e1.assign(expression_text);
        e2.assign(pre_expression);
        std::string in;
        in.assign(match_against);
        std::ostringstream t(std::ios::out | std::ios::binary);
        std::ostream_iterator<char, char> oi(t);
        boost::regex_replace(oi, in.begin(), in.end(),
            e2, format_string, boost::match_default | boost::format_all);
        std::string s(t.str());
#ifdef DEBUG
        std::cout << s << std::endl;
#endif
    } catch(...) {
    }
    return 0;
}

const char* pre_expression = "(<)|(>)|(&)|\\r";
const char* pre_format = "(?1&lt;)(?2&gt;)(?3&amp;)";


const char* expression_text =
    // preprocessor directives: index 1
    "(^[[:blank:]]*#(?:[^\\\\\\n]|\\\\[^\\n[:punct:][:word:]]*[\\n[:punct:][:word:]])*)|"
    // comment: index 2
    "(//[^\\n]*|/\\*.*?\\*/)|"
    // literals: index 3
    "\\<([+-]?(?:(?:0x[[:xdigit:]]+)|(?:(?:[[:digit:]]*\\.)?[[:digit:]]+"
    "(?:[eE][+-]?[[:digit:]]+)?))u?(?:(?:int(?:8|16|32|64))|L)?)\\>|"
    // string literals: index 4
    "('(?:[^\\\\']|\\\\.)*'|\"(?:[^\\\\\"]|\\\\.)*\")|"
    // keywords: index 5
    "\\<(__asm|__cdecl|__declspec|__export|__far16|__fastcall|__fortran|__import"
    "|__pascal|__rtti|__stdcall|_asm|_cdecl|__except|_export|_far16|_fastcall"
    "|__finally|_fortran|_import|_pascal|_stdcall|__thread|__try|asm|auto|bool"
    "|break|case|catch|cdecl|char|class|const|const_cast|continue|default|delete"
    "|do|double|dynamic_cast|else|enum|explicit|extern|false|float|for|friend|goto"
    "|if|inline|int|long|mutable|namespace|new|operator|pascal|private|protected"
    "|public|register|reinterpret_cast|return|short|signed|sizeof|static|static_cast"
    "|struct|switch|template|this|throw|true|try|typedef|typeid|typename|union|unsigned"
    "|using|virtual|void|volatile|wchar_t|while)\\>"
    ;


const char* match_against = "#include <iostream>"
"#include <string>"
"#include <vector>"
"#include <boost/regex.hpp>"
""
""
"extern \"C\" int main(int argc, char** argv) {"
"	  std::string regex_string;"
"	    std::getline(std::cin, regex_string);"
"	      std::string where(\"AAAA\");"
"	        try {"
"			    boost::regex e(regex_string);"
"			        std::cout << \"Regexp string: \" << regex_string << \"Size: \" << regex_string.size() << std::endl;"
"				    boost::match_results<std::string::const_iterator> what;"
"				        bool match = boost::regex_match(where, what, e, boost::match_default | boost::match_partial | boost::match_perl | boost::match_posix | boost::match_any);"
"					    if (match)"
"						    	    std::cout << match << std::endl;"
"					      }"
"		  catch (const std::runtime_error &err) {"
"			          std::cerr << \"Caught exception: \" << err.what() << std::endl;"
"				    }"
"		    return 0;"
"}";

