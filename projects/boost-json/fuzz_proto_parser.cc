// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "json.pb.h"
#include "json_proto_converter.h"
#include "src/libfuzzer/libfuzzer_macro.h"

#include <boost/json/parse_options.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/stream_parser.hpp>
#include <boost/json/monotonic_resource.hpp>
#include <boost/json/null_resource.hpp>
#include <boost/json/static_resource.hpp>
#include <boost/json/src.hpp>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

using namespace boost::json;

struct FuzzHelper {
    parse_options opt;
    string_view jsontext;
    std::size_t memlimit1;
    std::size_t memlimit2;
    bool res;
    void run(stream_parser& p) {
        error_code ec;

        // Write the first part of the buffer
        p.write( jsontext, ec);

        if(! ec)
            p.finish( ec );

        // Take ownership of the resulting value.
        if(! ec)
        {
            value jv = p.release();
            res=serialize(jv).size()==42;
        } else
            res=false;
    }

    // easy case - everything default
    void useDefault() {
        stream_parser p(storage_ptr{}, opt);
        run(p);
    }
};

void FuzzJson(std::string data_str, int32_t hash_settings) {
    FuzzHelper fh;

    // set parse options
    fh.opt.allow_comments = true;
    fh.opt.allow_trailing_commas = true;
    fh.opt.allow_invalid_utf8 = true;
    fh.opt.max_depth = 1000;

    //set the json string to parse
    fh.jsontext=string_view{data_str.c_str(), data_str.size()};
    try
    {
        fh.useDefault();
    }
    catch(...)
    {
    }
}

DEFINE_PROTO_FUZZER(const json_proto::JsonParseAPI &json_proto) {
    json_proto::JsonProtoConverter converter;
    std::string data_str = converter.Convert(json_proto.object_value());
    int32_t hash_settings = json_proto.settings();
    FuzzJson(data_str, hash_settings);
}