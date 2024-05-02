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
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/property_map/dynamic_property_map.hpp>
#include <boost/exception/exception.hpp>
#include <boost/exception/diagnostic_information.hpp>
#ifdef DEBUG
#include <iostream>
#endif
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

struct DotVertex {
    std::string name;
    std::string label;
    int peripheries;
};

struct DotEdge {
    std::string label;
};

typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS,
        DotVertex, DotEdge> graph_t;

using namespace boost;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try
    {
        graph_t graphviz;
        boost::dynamic_properties dp(boost::ignore_other_properties);
        dp.property("node_id", boost::get(&DotVertex::name, graphviz));
        read_graphviz(fdp.ConsumeRemainingBytesAsString(), graphviz, dp);
        auto viter = make_iterator_range(vertices(graphviz));
#ifdef DEBUG
        for (auto v : viter) {
            std::cout << v << " ";
        }
#endif
    } catch(...) {
    }
    return 0;
}
