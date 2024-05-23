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

#include <boost/beast.hpp>
#include <boost/beast/_experimental/test/stream.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    using namespace boost::beast;

    error_code ec;
    flat_buffer buffer;
    net::io_context ioc;
    test::stream remote{ioc};

    websocket::stream<test::stream> ws{
        ioc, string_view{reinterpret_cast<const char*>(data), size}};

    ws.set_option(
        websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(http::field::server, "websocket-server-sync");
        }));

    ws.set_option(websocket::permessage_deflate{
        .server_enable = (size % 2) != 0,
        .compLevel = static_cast<int>(size % 9),
    });

    ws.next_layer().connect(remote);
    ws.next_layer().close_remote();
    ws.accept(ec);

    if (!ec)
    {
        ws.read(buffer, ec);
        ws.text(ws.got_text());
        ws.write(buffer.data(), ec);
    }

    return 0;
}
