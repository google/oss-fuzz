#include "ProtoToGif.h"

using namespace gifProtoFuzzer;
using namespace std;

constexpr unsigned char ProtoConverter::m_sig[];
constexpr unsigned char ProtoConverter::m_ver89a[];
constexpr unsigned char ProtoConverter::m_ver87a[];

string ProtoConverter::gifProtoToString(GifProto const &proto)
{
	visit(proto);
	return m_output.str();
}

void ProtoConverter::visit(GifProto const &gif)
{
	visit(gif.header());
	visit(gif.lsd());
	if (m_hasGCT)
		visit(gif.gct());
	for (auto const &chunk : gif.chunks())
		visit(chunk);
	visit(gif.trailer());
}

void ProtoConverter::visit(Header const &header)
{
	// Signature GIF
	m_output.write((const char *)m_sig, sizeof(m_sig));

	switch (header.ver())
	{
	case Header::ENA:
		m_output.write((const char *)m_ver89a, sizeof(m_ver89a));
		break;
	case Header::ESA:
		m_output.write((const char *)m_ver87a, sizeof(m_ver87a));
		break;
	// We simply don't write anything if it's an invalid version
	// Bytes that follow (LSD) will be interpreted as version
	case Header::INV:
		break;
	}
}

void ProtoConverter::visit(LogicalScreenDescriptor const &lsd)
{
	writeWord(extractWordFromUInt32(lsd.screenwidth()));
	writeWord(extractWordFromUInt32(lsd.screenheight()));

	uint8_t packedByte = extractByteFromUInt32(lsd.packed());
	// If MSB of packed byte is 1, GCT follows
	if (packedByte & 0x80)
	{
		m_hasGCT = true;
		// N: 2^(N+1) colors in GCT
		m_globalColorExp = packedByte & 0x07;
	}
	writeByte(packedByte);
	writeByte(extractByteFromUInt32(lsd.backgroundcolor()));
	writeByte(extractByteFromUInt32(lsd.aspectratio()));
}

void ProtoConverter::visit(GlobalColorTable const &gct)
{
	//[TODO 27/04/2019 VU]: Should it really be exactly the same size? Or do we want some deterministic randomness here?
	// TODO BS: We never overflow expected table size due to the use of min
	uint32_t tableSize = min((uint32_t)gct.colors().size(), tableExpToTableSize(m_globalColorExp));
	m_output.write(gct.colors().data(), tableSize);
}

void ProtoConverter::visit(GraphicControlExtension const &gce)
{
	writeByte(0x21); // Extension Introducer
	writeByte(0xF9); // Graphic Control Label
	writeByte(4);	// Block size
	uint8_t packedByte = extractByteFromUInt32(gce.packed());
	// packed byte
	writeByte(packedByte);
	// Delay time is 2 bytes
	writeWord(extractWordFromUInt32(gce.delaytime()));
	// Transparent color index is 1 byte
	writeByte(extractByteFromUInt32(gce.transparentcolorindex()));
	writeByte(0x0); // Block Terminator
}

void ProtoConverter::visit(ImageChunk const &chunk)
{
	switch (chunk.chunk_oneof_case())
	{
	case ImageChunk::kBasic:
		visit(chunk.basic());
		break;
	case ImageChunk::kPlaintext:
		visit(chunk.plaintext());
		break;
	case ImageChunk::kAppExt:
		visit(chunk.appext());
		break;
	case ImageChunk::kComExt:
		visit(chunk.comext());
		break;
	case ImageChunk::CHUNK_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(const BasicChunk &chunk)
{
	// Visit GCExt if necessary
	if (chunk.has_gcext())
		visit(chunk.gcext());
	visit(chunk.imdescriptor());
	if (m_hasLCT)
		visit(chunk.lct());
	visit(chunk.img());
}

void ProtoConverter::visit(LocalColorTable const &lct)
{
	//[TODO 27/04/2019 VU]: Should it really be exactly the same size? Or do we want some deterministic randomness here?
	// TODO BS: We never overflow expected table size due to the use of min
	uint32_t tableSize = min((uint32_t)lct.colors().size(), tableExpToTableSize(m_localColorExp));
	m_output.write(lct.colors().data(), tableSize);
}

void ProtoConverter::visit(ImageDescriptor const &descriptor)
{
	// TODO: Remove seperator from proto since it is always 2C
	writeByte(0x2C);
	writeWord(extractWordFromUInt32(descriptor.left()));
	writeWord(extractWordFromUInt32(descriptor.top()));
	writeWord(extractWordFromUInt32(descriptor.height()));
	writeWord(extractWordFromUInt32(descriptor.width()));
	uint8_t packedByte = extractByteFromUInt32(descriptor.packed());
	if (packedByte & 0x80)
	{
		m_hasLCT = true;
		m_localColorExp = packedByte & 0x07;
	}
	else
		m_hasLCT = false;
}

void ProtoConverter::visit(SubBlock const &block)
{
	uint8_t len = extractByteFromUInt32(block.len());
	if (len == 0)
	{
		writeByte(0x00);
	}
	else
	{
		// TODO BS: We never overflow expected block size due to the use of min
		uint32_t write_len = min((uint32_t)len, (uint32_t)block.data().size());
		m_output.write(block.data().data(), write_len);
	}
}

void ProtoConverter::visit(ImageData const &img)
{
	// TODO: Verify we are writing the image data correctly
	// LZW
	writeByte(extractByteFromUInt32(img.lzw()));
	// Sub-blocks
	for (auto const &block : img.subs())
		visit(block);
	// NULL sub block signals end of image data
	writeByte(0x00);
}

void ProtoConverter::visit(PlainTextExtension const &ptExt)
{
	// Visit GCExt if necessary
	if (ptExt.has_gcext())
		visit(ptExt.gcext());

	// First two bytes are 0x21 0x01
	writeByte(0x21);
	writeByte(0x01);
	// Skip zero bytes
	writeByte(0x00);
	for (auto const &block : ptExt.subs())
		visit(block);
	// NULL sub block signals end
	writeByte(0x00);
}

void ProtoConverter::visit(CommentExtension const &comExt)
{
	// First two bytes are 0x21 0xFE
	writeByte(0x21);
	writeByte(0xFE);
	// Sub-blocks
	for (auto const &block : comExt.subs())
		visit(block);
	// NULL sub block signals end of image data
	writeByte(0x00);
}

void ProtoConverter::visit(ApplicationExtension const &appExt)
{
	// First two bytes are 0x21 0xFF
	writeByte(0x21);
	writeByte(0xFF);
	// Next, we write "11" decimal or 0x0B
	writeByte(0x0B);
	writeLong(appExt.appid());
	// We hardcode the auth code to 1.0 or 0x31 0x2E 0x30
	writeByte(0x31);
	writeByte(0x2E);
	writeByte(0x30);
	// Sub-blocks
	for (auto const &block : appExt.subs())
		visit(block);
	// NULL sub block signals end of image data
	writeByte(0x00);
}

void ProtoConverter::visit(Trailer const &)
{
	writeByte(0x3B);
}

// =============================================================
// Utility functions
// =============================================================
void ProtoConverter::writeByte(uint8_t x)
{
	m_output.write((char *)&x, sizeof(x));
}

void ProtoConverter::writeWord(uint16_t x)
{
	m_output.write((char *)&x, sizeof(x));
}

void ProtoConverter::writeInt(uint32_t x)
{
	m_output.write((char *)&x, sizeof(x));
}

void ProtoConverter::writeLong(uint64_t x)
{
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

/**
 * Given an exponent, returns the global/local color table size, given by 3*2^(exp+1)
 * @param tableExp The exponent
 * @return The actual color table size
 */
uint32_t ProtoConverter::tableExpToTableSize(uint32_t tableExp)
{
	// 0 <= tableExp <= 7
	// 6 <= tableSize <= 768
	uint32_t tableSize = 3 * (pow(2, tableExp + 1));
	return tableSize;
}
