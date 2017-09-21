// From https://svn.boost.org/trac10/ticket/12818
// This fuzz target can likely be enhanced to exercise more code.
// The ideal place for this fuzz target is the bost repository.
#include <boost/regex.hpp>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  try {
    std::string str((char *)Data, Size);
    boost::regex e(str);
    boost::match_results<std::string::const_iterator> what;
    boost::regex_match(str, what, e,
                       boost::match_default | boost::match_partial);

  } catch (const std::exception &) {
  }
  return 0;
}
