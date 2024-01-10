// The ideal place for this fuzz target is the boost repository.
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphml.hpp>
#include <boost/range/irange.hpp>
#ifdef DEBUG
#include <iostream>
#endif
#include <string>
#include <sstream>
#include <fuzzer/FuzzedDataProvider.h>

typedef boost::adjacency_list<
    boost::vecS, boost::vecS, boost::directedS,
    boost::property<boost::vertex_name_t, std::string>,
    boost::property<boost::edge_weight_t, double>
> Graph;

using namespace boost;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try
    {
        Graph g;
        boost::dynamic_properties dp(boost::ignore_other_properties);
        std::stringstream input(fdp.ConsumeRemainingBytesAsString());
        read_graphml(input, g, dp);
        auto viter = make_iterator_range(vertices(g));
#ifdef DEBUG
        for (auto v : viter) {
            std::cout << v << " ";
        }
#endif
    } catch(...) {
    }
    return 0;
}
