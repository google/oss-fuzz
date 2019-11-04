#pragma once

#include "xercesc/parsers/SAXParser.hpp"
#include "xercesc/framework/MemBufInputSource.hpp"
#include "xercesc/util/OutOfMemoryException.hpp"

void parseInMemory(const uint8_t *Data, size_t Size);