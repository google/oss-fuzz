// The ideal place for this fuzz target is the boost repository.
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        boost::filesystem::path p(fdp.ConsumeRandomLengthString(5));

        p.replace_filename(fdp.ConsumeRandomLengthString(5));
        
        p.has_extension();
        p.extension();
        p.replace_extension(fdp.ConsumeRandomLengthString(3));
        
        boost::filesystem::path p1(fdp.ConsumeRandomLengthString(5));
        p.concat(p1);
        p.append(p1);
        p.remove_filename_and_trailing_separators();
        p /= (p1);
        p += (p1);
        
        p.lexically_relative(p1);
        p.filename_is_dot();
        p.remove_filename();
        
        p.swap(p1);
        p.root_directory();
        p.relative_path();
        p.parent_path();
        p.has_stem();
    } catch(...) {
    }
    return 0;
}