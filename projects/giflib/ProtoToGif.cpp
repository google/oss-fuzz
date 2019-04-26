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
	if (m_hasGCT)
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
	writeWord(extractWordFromUInt32(lsd.screenwidth()));
	writeWord(extractWordFromUInt32(lsd.screenheight()));

	uint8_t packedByte = extractByteFromUInt32(lsd.packed());
	// If MSB of packed byte is 1, GCT follows
	if (packedByte & 0x80) {
		m_hasGCT = true;
		// N: 2^(N+1) colors in GCT
		m_globalColorExp = packedByte & 0x07;
	}
	writeByte(packedByte);
	writeByte(extractByteFromUInt32(lsd.backgroundcolor()));
	writeByte(extractByteFromUInt32(lsd.aspectratio()));
}

void ProtoConverter::visit(GlobalColorTable const& gct)
{
	// TODO: This has to contain exactly 3*2^(m_GlobalColorExp + 1) bytes
	m_output.write(gct.colors().data(), gct.colors().size());
}

void ProtoConverter::visit(LocalColorTable const& lct)
{
	// TODO: This has to contain exactly 3*2^(m_LocalColorExp + 1) bytes
	m_output.write(lct.colors().data(), lct.colors().size());
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
	writeByte(0x3B);
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

uint16_t ProtoConverter::extractWordFromUInt32(uint32_t a)
{
	uint16_t first_byte = (a & 0xFF);
	uint16_t second_byte = ((a >> 8) & 0xFF) << 8;
	return first_byte | second_byte;
}

uint8_t ProtoConverter::extractByteFromUInt32(uint32_t a)
{
	uint8_t byte = a & 0x80;
	return byte;
}

void ProtoConverter::visit(SubBlock const& block)
{
	uint8_t len = extractByteFromUInt32(block.len());
	if (len == 0)
		writeByte(0x00);
	else
		m_output.write(block.data().data(), block.data().size());
}

void ProtoConverter::visit(ImageData const& img)
{
	// TODO: Verify we are writing the image data correctly
	// LZW
	writeByte(extractByteFromUInt32(img.lzw()));
	// Sub-blocks
	for (auto const& block: img.subs())
		visit(block);
	// NULL sub block signals end of image data
	writeByte(0x00);
}

void ProtoConverter::writeBasicChunk(const BasicChunk &chunk)
{
	// TODO: Convert graphic control extension
	visit(chunk.imdescriptor());
	if(m_hasLCT)
		visit(chunk.lct());
	visit(chunk.img());
}

void ProtoConverter::visit(ImageDescriptor const& descriptor)
{
	// TODO: Remove seperator from proto since it is always 2C
	writeByte(0x2C);
	writeWord(extractWordFromUInt32(descriptor.left()));
	writeWord(extractWordFromUInt32(descriptor.top()));
	writeWord(extractWordFromUInt32(descriptor.height()));
	writeWord(extractWordFromUInt32(descriptor.width()));
	uint8_t packedByte = extractByteFromUInt32(descriptor.packed());
	if (packedByte & 0x80) {
		m_hasLCT = true;
		m_localColorExp = packedByte & 0x07;
	}
}