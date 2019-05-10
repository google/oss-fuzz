#include <boost/multiprecision/cpp_int.hpp>
#include <boost/range/algorithm_ext/erase.hpp>

using namespace std;
using namespace boost::multiprecision;

template <unsigned numBits, cpp_integer_type type, cpp_int_check_type validation>
using fixedNum = number<cpp_int_backend<numBits, numBits, type, validation, void> >;

template <typename T>
void
add(T const& arg1, T const& arg2)
{
	T result = arg1 + arg2;
	cpp_int arbitP = cpp_int(arg1) + cpp_int(arg2);
	assert(static_cast<T>(arbitP) == result);
}

template <typename T>
void
stringToTwoCppInts(string input, T& arg1, T& arg2)
{
	size_t Size = input.size();

	try {
		arg1 = T(input.substr(0, Size/2));
		arg2 = T(input.substr(Size/2, Size));
	}
	catch (runtime_error const&)
	{
	}
}

template <typename T>
void test(T const& arg1, T const& arg2)
{
	add(arg1, arg2);
}

string removeNonDigitsFromString(string input)
{
        string digits{input};
        if (!digits.empty())
        {
                boost::range::remove_erase_if(digits, [=](char c) -> bool {
                        return !isdigit(c);
                });
        }
        return digits;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	if (Size < 100)
		return 0;

	string input(reinterpret_cast<char const*>(Data), Size);
	string number = removeNonDigitsFromString(input);
	if (number.size() < 100)
		return 0;

	{
		fixedNum<256, unsigned_magnitude, unchecked> arg1;
		fixedNum<256, unsigned_magnitude, unchecked> arg2;
		stringToTwoCppInts(number, arg1, arg2);
		test(arg1, arg2);
	}
	return 0;
}
