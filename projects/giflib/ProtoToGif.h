#include <string>
#include <sstream>
#include <cmath>
#include <algorithm>
#include "gif_fuzz_proto.pb.h"

namespace gifProtoFuzzer
{
class ProtoConverter
{
  public:
	std::string gifProtoToString(GifProto const &proto);

  private:
	template <class T>
	void visit(google::protobuf::RepeatedPtrField<T> const &_repeated_field);
	void visit(const GifProto &);
	void visit(const Header &);
	void visit(const LogicalScreenDescriptor &);
	void visit(const GlobalColorTable &);
	void visit(const ImageChunk &);
	void visit(const BasicChunk &);
	void visit(const ImageData &);
	void visit(const SubBlock &);
	void visit(const ImageDescriptor &);
	void visit(const LocalColorTable &);
	void visit(const GraphicControlExtension &);
	void visit(const PlainTextExtension &);
	void visit(const ApplicationExtension &);
	void visit(const CommentExtension &);
	void visit(const Trailer &);

	// Utility functions
	void writeByte(uint8_t x);
	void writeWord(uint16_t x);
	void writeInt(uint32_t x);
	void writeLong(uint64_t x);
	static uint16_t extractWordFromUInt32(uint32_t a);
	static uint8_t extractByteFromUInt32(uint32_t a);
	static uint32_t tableExpToTableSize(uint32_t tableExp);

	std::stringstream m_output;
	bool m_hasGCT = false;
	bool m_hasLCT = false;
	uint8_t m_globalColorExp = 0;
	uint8_t m_localColorExp = 0;

	static constexpr unsigned char m_sig[] = {0x47, 0x49, 0x46};
	static constexpr unsigned char m_ver89a[] = {0x38, 0x39, 0x61};
	static constexpr unsigned char m_ver87a[] = {0x38, 0x37, 0x61};
};
} // namespace gifProtoFuzzer