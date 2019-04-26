#include "ProtoToGif.h"

using namespace gifProtoFuzzer;

std::string ProtoConverter::gifProtoToString(GifProto const& proto)
{
	visit(proto);
	return m_output.str();
}

void ProtoConverter::visit(GifProto const& gif)
{
	visit(gif.header());
	visit(gif.lsd());
	if (gif.has_gct())
		visit(gif.gct());
	for (auto const& chunk: gif.chunks())
		visit(chunk);
	visit(gif.trailer());
}

void ProtoConverter::visit(Header const&)
{
	const unsigned char header[] = {0x47,0x49,0x46,0x38,0x39,0x61};
	m_output.write((const char*)header, sizeof(header));
}

void ProtoConverter::visit(LogicalScreenDescriptor const& lsd)
{
	uint16_t w = extractTwo(lsd.screenwidth());
	uint16_t h = extractTwo(lsd.screenheight());
	writeWord(w);
	writeWord(h);
	writeByte(lsd.packed());
	writeByte(lsd.backgroundcolor());
	writeByte(lsd.aspectratio());
}

void ProtoConverter::visit(GlobalColorTable const& gct)
{
	m_output.write(gct.colors().data(), gct.colors().size());
}

void ProtoConverter::visit(BasicChunk const& chunk)
{
	writeBasicChunk(chunk);
}

void ProtoConverter::visit(GraphicControlExtension const&)
{
}

void ProtoConverter::visit(ImageChunk const& chunk)
{
	// TODO: Implement converters for different chunk types
	switch (chunk.chunk_oneof_case())
	{
		case ImageChunk::kBasic:
			writeBasicChunk(chunk.basic());
			break;
		case ImageChunk::kPlaintext:
			break;
		case ImageChunk::kAppExt:
			break;
		case ImageChunk::kComExt:
			break;
		case ImageChunk::CHUNK_ONEOF_NOT_SET:
			break;
	}
}

void ProtoConverter::visit(PlainTextChunk const&)
{

}

void ProtoConverter::visit(CommentExtension const&)
{

}

void ProtoConverter::visit(ApplicationExtension const&)
{

}

void ProtoConverter::visit(Trailer const&)
{
	const unsigned char trailer[] = {0x3B};
	m_output.write((const char*)trailer, sizeof(trailer));
}

void ProtoConverter::writeByte(uint8_t x)
{
	m_output.write((char *)&x, sizeof(x));
}

void ProtoConverter::writeWord(uint16_t x)
{
	x = __builtin_bswap16(x);
	m_output.write((char *)&x, sizeof(x));
}

void ProtoConverter::writeInt(uint32_t x)
{
	x = __builtin_bswap32(x);
	m_output.write((char *)&x, sizeof(x));
}

uint16_t ProtoConverter::extractTwo(uint32_t a)
{
	uint16_t first_byte = (a & 0xFF);
	uint16_t second_byte = ((a >> 8) & 0xFF) << 8;
	return first_byte | second_byte;
}

void ProtoConverter::writeBasicChunk(const BasicChunk &chunk)
{
	// TODO: Convert graphic control extension
	auto &imDescriptor = chunk.imdescriptor();
	writeByte(imDescriptor.seperator());
	uint16_t l = extractTwo(imDescriptor.left());
	uint16_t t = extractTwo(imDescriptor.top());
	uint16_t w = extractTwo(imDescriptor.height());
	uint16_t h = extractTwo(imDescriptor.width());
	writeWord(l);
	writeWord(t);
	writeWord(w);
	writeWord(h);
	writeByte(imDescriptor.packed());
	if(chunk.has_localcolortable()){
		m_output.write(chunk.localcolortable().data(),chunk.localcolortable().size());
	}
	m_output.write(chunk.imagedata().data(),chunk.imagedata().size());
}