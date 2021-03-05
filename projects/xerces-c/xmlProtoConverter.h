/*
 * Copyright (C) 2019 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sstream>

#include "xml.pb.h"

namespace xmlProtoFuzzer {
class ProtoConverter
{
public:
	ProtoConverter() = default;

	ProtoConverter(ProtoConverter const&) = delete;

	ProtoConverter(ProtoConverter&&) = delete;

	std::string protoToString(XmlDocument const&);

private:
	void visit(Prolog const&);

	void visit(ProcessingInstruction const&);

	void visit(ExternalId const&);

	void visit(DocTypeDecl const&);

	void visit(VersionNum const&);

	void visit(Encodings const&);

	void visit(Misc const&);

	void visit(KeyValue const&);

	void visit(Element const&);

	void visit(ElementDecl const&);

	void visit(AttValue const&);

	void visit(DefaultDecl const&);

	void visit(AttDef const&);

	void visit(AttListDecl const&);

	void visit(NotationDecl const&);

	void visit(EntityDecl const&);

	void visit(EntityValue const&);

	void visit(EntityDef const&);

	void visit(PEDef const&);

	void visit(NDataDecl const&);

	void visit(ConditionalSect const&);

	void visit(OneExtSubsetDecl const&);

	void visit(ExtSubsetDecl const&);

	void visit(MarkupDecl const&);

	void visit(CData const&);

	void visit(Content const&);

	void visit(XmlDeclaration const&);

	void visit(XmlDocument const&);

	template <typename T>
	bool isValid(T const& messageType) {
		return T::Type_IsValid(messageType.type());
	}

	std::string removeNonAscii(std::string const&);
	std::string getUri(Element_Id _x);
	std::string getPredefined(Element_Id _x, std::string const&);

	std::ostringstream m_output;

	static constexpr auto s_XInclude = "xmlns:xi=\"http://www.w3.org/2001/XInclude\"";
};
}

