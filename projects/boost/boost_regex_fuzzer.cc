// From https://svn.boost.org/trac10/ticket/12818
// This fuzz target can likely be enhanced to exercise more code.
// The ideal place for this fuzz target is the boost repository.
#ifdef DEBUG
#include <iostream>
#endif
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

namespace {
  void assertPostConditions(boost::match_results<std::string::const_iterator> const& match, boost::regex const& e)
  {
    // See https://www.boost.org/doc/libs/1_71_0/libs/regex/doc/html/boost_regex/ref/regex_match.html
    assert(match.size() == e.mark_count() + 1);
    assert(!match.empty());
    assert(!match.prefix().matched);
    assert(!match.suffix().matched);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  try {
    std::string str((char *)Data, Size);
    std::vector<std::string> strVector;
    // Split fuzz input string by space
    boost::split(strVector, str, [](char c){return c == ' ';});
    // Bail if vector contains fewer than two items
    if (strVector.size() < 2)
      return 0;

    // First item is regexp pattern
    boost::regex e(strVector[0]);
    // Second (until last item concatenated) is string to be checked
    std::string text;
    for(std::vector<std::string>::const_iterator it = strVector.begin() + 1; it != strVector.end(); ++it)
      text += *it;
#ifdef DEBUG
    std::cout << "Regexp: " << strVector[0] << "Size: " << strVector[0].size() << std::endl;
    std::cout << "Text: " << text << "Size: " << text.size() << std::endl;
#endif

    boost::match_results<std::string::const_iterator> what;
    bool match = boost::regex_match(text, what, e,
                       boost::match_default | boost::match_partial);
    if (match)
      assertPostConditions(what, e);
  }
  catch (const std::runtime_error &) {
  }
  return 0;
}
