// The ideal place for this fuzz target is the boost repository.
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <sstream>
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

po::options_description set_options()
{
    po::options_description opts;
    opts.add_options()
        ("global_string", po::value<string>())

        ("strings.word", po::value<string>())
        ("strings.phrase", po::value<string>())
        ("strings.quoted", po::value<string>())

        ("ints.positive", po::value<int>())
        ("ints.negative", po::value<int>())
        ("ints.hex", po::value<int>())
        ("ints.oct", po::value<int>())
        ("ints.bin", po::value<int>())

        ("floats.positive", po::value<float>())
        ("floats.negative", po::value<float>())
        ("floats.double", po::value<double>())
        ("floats.int", po::value<float>())
        ("floats.int_dot", po::value<float>())
        ("floats.dot", po::value<float>())
        ("floats.exp_lower", po::value<float>())
        ("floats.exp_upper", po::value<float>())
        ("floats.exp_decimal", po::value<float>())
        ("floats.exp_negative", po::value<float>())
        ("floats.exp_negative_val", po::value<float>())
        ("floats.exp_negative_negative_val", po::value<float>())

        ("booleans.number_true", po::bool_switch())
        ("booleans.number_false", po::bool_switch())
        ("booleans.yn_true", po::bool_switch())
        ("booleans.yn_false", po::bool_switch())
        ("booleans.tf_true", po::bool_switch())
        ("booleans.tf_false", po::bool_switch())
        ("booleans.onoff_true", po::bool_switch())
        ("booleans.onoff_false", po::bool_switch())
        ("booleans.present_equal_true", po::bool_switch())
       ("booleans.present_no_equal_true", po::bool_switch())
       ;
    return opts;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    try {
        FuzzedDataProvider fdp(data, size);
        auto opts = set_options();
        po::variables_map vars;
        stringstream st(fdp.ConsumeRemainingBytesAsString());

        const bool ALLOW_UNREGISTERED = true;

        po::parsed_options parsed = parse_config_file(st, opts, ALLOW_UNREGISTERED);
        store(parsed, vars);
        vector<string> unregistered = po::collect_unrecognized(parsed.options, po::exclude_positional);
        notify(vars);
    } catch(...) {
    }
    return 0;
}