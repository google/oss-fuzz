// The ideal place for this fuzz target is the boost repository.
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/find_iterator.hpp>
#include <boost/throw_exception.hpp>
#include <string>
#include <iterator>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    try{
        FuzzedDataProvider fdp(Data, Size);
        std::string x = fdp.ConsumeRemainingBytesAsString();

        boost::algorithm::to_upper_copy(x);
        boost::algorithm::trim_copy(x);
        boost::algorithm::replace_all_copy(x, "A", "LHVBSLDFVSDJHKG");

        typedef boost::algorithm::find_iterator<std::string::iterator> string_find_iterator;
        for(string_find_iterator It=boost::algorithm::make_find_iterator(x, boost::algorithm::first_finder("A", boost::algorithm::is_iequal()));
            It!=string_find_iterator();
            ++It
            ){
                boost::copy_range<std::string>(*It);
        }

        typedef boost::algorithm::split_iterator<std::string::iterator> string_split_iterator;
        for(string_split_iterator It=boost::algorithm::make_split_iterator(x, boost::algorithm::first_finder(" ", boost::algorithm::is_iequal()));
            It!=string_split_iterator();
            ++It
            ){
                boost::copy_range<std::string>(*It);
        }

        boost::algorithm::erase_all_copy(x, "A");
        boost::algorithm::erase_head_copy(x, 2147483647);
        boost::algorithm::erase_head_copy(x, -2147483648);
        boost::algorithm::erase_tail_copy(x, 2147483647);
        boost::algorithm::erase_tail_copy(x, -2147483648);

    } catch(...) {
    }
    return 0;
}
