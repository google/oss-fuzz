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

#include "xmlProtoConverter.h"

#include <algorithm>

using namespace std;
using namespace xmlProtoFuzzer;

string ProtoConverter::removeNonAscii(string const& _utf8)
{
	string asciiStr{_utf8};
	asciiStr.erase(remove_if(asciiStr.begin(), asciiStr.end(), [=](char c) -> bool {
                        return !(std::isalpha(c) || std::isdigit(c));
                }), asciiStr.end());
	return asciiStr.empty() ? "fuzz" : asciiStr;
}


void ProtoConverter::visit(Misc const& _x)
{
	switch (_x.misc_oneof_case())
	{
	case Misc::kComment:
		m_output << "<!--" << _x.comment() << "-->\n";
		break;
	case Misc::kInst:
		visit(_x.inst());
		break;
	case Misc::MISC_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(Prolog const& _x)
{
	visit(_x.decl());
	visit(_x.doctype());
	for (auto const& misc: _x.misc())
		visit(misc);
}

void ProtoConverter::visit(KeyValue const& _x)
{
	if (!KeyValue::XmlNamespace_IsValid(_x.type()))
		return;

	switch (_x.type())
	{
	case KeyValue::ATTRIBUTES:
		m_output << "xml:attributes=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::BASE:
		m_output << "xml:base=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::CATALOG:
		m_output << "xml:catalog=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::ID:
		m_output << "xml:id=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::LANG:
		m_output << "xml:lang=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::LINK:
		m_output << "xml:link=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::SPACE:
		m_output << "xml:space=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::SPECIAL:
		m_output << "xml:special=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::TEST:
		m_output << "xml:test=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue::FUZZ:
		if (_x.ByteSizeLong() % 2)
			m_output << "xmlns:" << removeNonAscii(_x.key()) << "=\"" << removeNonAscii(_x.value()) << "\" ";
		else
			m_output << removeNonAscii(_x.key()) << "=\"" << removeNonAscii(_x.value()) << "\" ";
		break;
	case KeyValue_XmlNamespace_KeyValue_XmlNamespace_INT_MIN_SENTINEL_DO_NOT_USE_:
	case KeyValue_XmlNamespace_KeyValue_XmlNamespace_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
}

void ProtoConverter::visit(ProcessingInstruction const& _x)
{
	m_output << "<?" << removeNonAscii(_x.name()) << " ";
	for (auto const& prop: _x.kv())
		visit(prop);
	m_output << "?>\n";
}

void ProtoConverter::visit(Content const& _x)
{
	switch (_x.content_oneof_case())
	{
	case Content::kStr:
		m_output << _x.str() << "\n";
		break;
	case Content::kE:
		visit(_x.e());
		m_output << "\n";
		break;
	case Content::kC:
		visit(_x.c());
		m_output << "\n";
		break;
	case Content::CONTENT_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(ElementDecl const& _x)
{
	if (!ElementDecl::ContentSpec_IsValid(_x.spec()))
		return;

	m_output << "<!ELEMENT " << _x.name() << " ";
	switch (_x.spec())
	{
	case ElementDecl::EMPTY:
		m_output << "EMPTY>";
		break;
	case ElementDecl::ANY:
		m_output << "ANY>";
		break;
	case ElementDecl::FUZZ:
		m_output << "FUZZ>";
		break;
	case ElementDecl::MIXED:
		m_output << "(#PCDATA";
		for (auto const& pcdata: _x.cdata())
			m_output << "|" << pcdata;
		m_output << ")";
		if (_x.cdata_size() > 0)
			m_output << "*";
		m_output << ">";
		break;
	case ElementDecl::CHILDREN:
	{
		m_output << "(";
		string delim = "";
		for (auto const& str: _x.cdata()) {
			m_output << delim << removeNonAscii(str);
			delim = ", ";
		}
		m_output << ")>";
		break;
	}
	case ElementDecl_ContentSpec_ElementDecl_ContentSpec_INT_MIN_SENTINEL_DO_NOT_USE_:
	case ElementDecl_ContentSpec_ElementDecl_ContentSpec_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
}

void ProtoConverter::visit(AttValue const& _x)
{
	if (!isValid(_x))
		return;

	m_output << "\"";
	string prefix;
	switch (_x.type())
	{
	case AttValue::ENTITY:
		prefix = "&";
		break;
	case AttValue::CHAR:
		if (_x.ByteSizeLong() % 2)
			prefix = "&#";
		else
			// TODO: Value that follows this must be a
			// sequence of hex digits.
			prefix = "&#x";
		break;
	case AttValue::FUZZ:
		prefix = "fuzz";
		break;
	case AttValue_Type_AttValue_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case AttValue_Type_AttValue_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
	for (auto const& name: _x.value())
		m_output << prefix << removeNonAscii(name) << ";";
	m_output << "\"";
}

void ProtoConverter::visit(DefaultDecl const& _x)
{
	if (!isValid(_x))
		return;

	switch (_x.type())
	{
	case DefaultDecl::REQUIRED:
		m_output << "#REQUIRED";
		break;
	case DefaultDecl::IMPLIED:
		m_output << "#IMPLIED";
		break;
	case DefaultDecl::FIXED:
		m_output << "#FIXED ";
		visit(_x.att());
		break;
	case DefaultDecl::FUZZ:
		m_output << "#FUZZ";
		break;
	case DefaultDecl_Type_DefaultDecl_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case DefaultDecl_Type_DefaultDecl_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
}

void ProtoConverter::visit(AttDef const& _x)
{
	if (!isValid(_x))
		return;

	m_output << " " << removeNonAscii(_x.name()) << " ";
	switch (_x.type())
	{
	case AttDef::CDATA:
		m_output << "CDATA ";
		break;
	case AttDef::ID:
		m_output << "ID ";
		break;
	case AttDef::IDREF:
		m_output << "IDREF ";
		break;
	case AttDef::IDREFS:
		m_output << "IDREFS ";
		break;
	case AttDef::ENTITY:
		m_output << "ENTITY ";
		break;
	case AttDef::ENTITIES:
		m_output << "ENTITIES ";
		break;
	case AttDef::NMTOKEN:
		m_output << "NMTOKEN ";
		break;
	case AttDef::NMTOKENS:
		m_output << "NMTOKENS ";
		break;
	case AttDef::FUZZ:
		m_output << "FUZZ ";
		break;
	case AttDef_Type_AttDef_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case AttDef_Type_AttDef_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
	visit(_x.def());
}

void ProtoConverter::visit(AttListDecl const& _x)
{
	m_output << "<!ATTLIST " << removeNonAscii(_x.name());
	for (auto const& att: _x.attdefs())
		visit(att);
	m_output << ">";
}

void ProtoConverter::visit(NotationDecl const& _x)
{
	m_output << "<!NOTATION " << removeNonAscii(_x.name()) << " ";
	switch (_x.notation_oneof_case())
	{
	case NotationDecl::kExt:
		visit(_x.ext());
		break;
	case NotationDecl::kPub:
		m_output << "PUBLIC " << _x.pub();
		break;
	case NotationDecl::kFuzz:
		m_output << "FUZZ " << _x.fuzz();
		break;
	case NotationDecl::NOTATION_ONEOF_NOT_SET:
		break;
	}
	m_output << ">";
}

void ProtoConverter::visit(NDataDecl const& _x)
{
	m_output << " NDATA " << _x.name();
}

void ProtoConverter::visit(EntityDef const& _x)
{
	switch (_x.entity_oneof_case())
	{
	case EntityDef::kExt:
		visit(_x.ext());
		if (_x.ByteSizeLong() % 2)
			visit(_x.ndata());
		break;
	case EntityDef::kVal:
		visit(_x.val());
		break;
	case EntityDef::ENTITY_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(PEDef const& _x)
{
	switch (_x.pedef_oneof_case())
	{
	case PEDef::kVal:
		visit(_x.val());
		break;
	case PEDef::kId:
		visit(_x.id());
		break;
	case PEDef::PEDEF_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(EntityValue const& _x)
{
	if (!isValid(_x))
		return;

	m_output << "\"";
	string prefix;
	switch (_x.type())
	{
	case EntityValue::ENTITY:
		prefix = "&";
		break;
	case EntityValue::CHAR:
		if (_x.ByteSizeLong() % 2)
			prefix = "&#";
		else
			prefix = "&#x";
		break;
	case EntityValue::PEREF:
		prefix = "%";
		break;
	case EntityValue::FUZZ:
		prefix = "fuzz";
		break;
	case EntityValue_Type_EntityValue_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case EntityValue_Type_EntityValue_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
	for (auto const& ref: _x.name())
		m_output << prefix << ref << ";";
	m_output << "\"";
}

void ProtoConverter::visit(EntityDecl const& _x)
{
	if (!isValid(_x))
		return;

	m_output << "<!ENTITY ";
	switch (_x.type())
	{
	case EntityDecl::GEDECL:
		m_output << _x.name() << " ";
		visit(_x.ent());
		break;
	case EntityDecl::PEDECL:
		m_output << "% " << _x.name() << " ";
		visit(_x.pedef());
		break;
	case EntityDecl_Type_EntityDecl_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case EntityDecl_Type_EntityDecl_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
	m_output << ">";
}

void ProtoConverter::visit(ConditionalSect const& _x)
{
	if (!isValid(_x))
		return;

	switch (_x.type())
	{
	case ConditionalSect::INCLUDE:
		m_output << "<![ INCLUDE [";
		visit(_x.ext());
		m_output << "]]>";
		break;
	case ConditionalSect::IGNORE:
		m_output << "<![ IGNORE [";
		for (auto const& str: _x.ignores())
			m_output << "<![" << removeNonAscii(str) << "]]>";
		m_output << "]]>";
		break;
	case ConditionalSect::FUZZ:
		m_output << "<![ FUZZ [";
		visit(_x.ext());
		m_output << "]]>";
		break;
	case ConditionalSect_Type_ConditionalSect_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case ConditionalSect_Type_ConditionalSect_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
}


void ProtoConverter::visit(OneExtSubsetDecl const& _x)
{
	switch (_x.extsubset_oneof_case())
	{
	case OneExtSubsetDecl::kM:
		visit(_x.m());
		break;
	case OneExtSubsetDecl::kC:
		visit(_x.c());
		break;
	case OneExtSubsetDecl::EXTSUBSET_ONEOF_NOT_SET:
		break;
	}
}


void ProtoConverter::visit(ExtSubsetDecl const& _x)
{
	for (auto const& decl: _x.decls())
		visit(decl);
}

void ProtoConverter::visit(CData const& _x)
{
	m_output << "<![CDATA[" << removeNonAscii(_x.data()) << "]]>";
}

void ProtoConverter::visit(MarkupDecl const& _x)
{
	switch (_x.markup_oneof_case())
	{
	case MarkupDecl::kE:
		visit(_x.e());
		break;
	case MarkupDecl::kA:
		visit(_x.a());
		break;
	case MarkupDecl::kN:
		visit(_x.n());
		break;
	case MarkupDecl::kM:
		visit(_x.m());
		break;
	case MarkupDecl::kEntity:
		visit(_x.entity());
		break;
	case MarkupDecl::kExt:
		visit(_x.ext());
		break;
	case MarkupDecl::MARKUP_ONEOF_NOT_SET:
		break;
	}
}

/// Returns predefined element from an Element_Id enum
/// @param _x is an enum that holds the desired type of predefined value
/// @param _prop is a string that holds the value of the desired type
/// @return string holding the predefined value of the form
/// name attribute=\"value\"
string ProtoConverter::getPredefined(Element_Id _x, string const& _prop)
{
	string output{};
	switch (_x)
	{
	case Element::XIINCLUDE:
	case Element::XIFALLBACK:
	case Element::XIHREF:
		output = "xi:include href=\"fuzz.xml\"";
	case Element::XIPARSE:
		output = "xi:include parse=\"xml\"";
	case Element::XIXPOINTER:
		output = "xi:include xpointer=\"" + removeNonAscii(_prop) + "\"";
	case Element::XIENCODING:
		output = "xi:include encoding=\"" + removeNonAscii(_prop) + "\"";
	case Element::XIACCEPT:
		output = "xi:include accept=\"" + removeNonAscii(_prop) + "\"";
	case Element::XIACCEPTLANG:
		output = "xi:include accept-language=\"" + removeNonAscii(_prop) + "\"";
	case Element_Id_Element_Id_INT_MIN_SENTINEL_DO_NOT_USE_:
	case Element_Id_Element_Id_INT_MAX_SENTINEL_DO_NOT_USE_:
		output = "xi:fuzz xifuzz=\"fuzz\"";
	}
	return output;
}

/// Returns uri string for a given Element_Id type
string ProtoConverter::getUri(Element_Id _x)
{
	if (!Element::Id_IsValid(_x))
		return s_XInclude;

	switch (_x)
	{
	case Element::XIINCLUDE:
	case Element::XIFALLBACK:
	case Element::XIHREF:
	case Element::XIPARSE:
	case Element::XIXPOINTER:
	case Element::XIENCODING:
	case Element::XIACCEPT:
	case Element::XIACCEPTLANG:
	case Element_Id_Element_Id_INT_MIN_SENTINEL_DO_NOT_USE_:
	case Element_Id_Element_Id_INT_MAX_SENTINEL_DO_NOT_USE_:
		return s_XInclude;
	}
}

void ProtoConverter::visit(Element const& _x)
{
	if (!isValid(_x))
		return;

	// Predefined child node
	string child = {};
	// Predefined uri for child node
	string pUri = {};
	// Element name
	string name = removeNonAscii(_x.name());

	switch (_x.type())
	{
	case Element::PREDEFINED:
		child = getPredefined(_x.id(), _x.childprop());
		pUri = getUri(_x.id());
		break;
	case Element::FUZZ:
	case Element_Type_Element_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case Element_Type_Element_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}

	// <name k1=v1 k2=v2 k3=v3>
	// <content>
	// </name>

	// Start name tag: Must be Ascii?
	m_output << "<" << name << " ";

	// Add uri to name tag
	if (!pUri.empty())
		m_output << pUri << " ";
	for (auto const& prop: _x.kv())
		visit(prop);
	m_output << ">\n";

	// Add attribute
	if (!child.empty())
		m_output << "<" << child << "/>\n";

	// Add content
	visit(_x.content());

	// Close name tag
	m_output << "</" << name << ">\n";
}

void ProtoConverter::visit(ExternalId const& _x)
{
	if (!isValid(_x))
		return;

	switch (_x.type())
	{
	case ExternalId::SYSTEM:
		m_output << "SYSTEM " << "\"" << removeNonAscii(_x.system()) << "\"";
		break;
	case ExternalId::PUBLIC:
		m_output << "PUBLIC " << "\"" << removeNonAscii(_x.pub()) << "\""
			<< " " << "\"" << removeNonAscii(_x.system()) << "\"";
		break;
	case ExternalId::FUZZ:
		m_output << "FUZZ " << "\"" << removeNonAscii(_x.pub()) << "\"";
		break;
	case ExternalId_Type_ExternalId_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case ExternalId_Type_ExternalId_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
}

void ProtoConverter::visit(DocTypeDecl const& _x)
{
	m_output << "<!DOCTYPE " << removeNonAscii(_x.name()) << " ";
	visit(_x.ext());
	m_output << "[";
	for (auto const& m: _x.mdecl())
		visit(m);
	m_output << "]";
	m_output << ">\n";
}

void ProtoConverter::visit(VersionNum const& _x)
{
	if (!isValid(_x))
		return;

	switch (_x.type())
	{
	case VersionNum::STANDARD:
		m_output << "\"1.0\"";
		break;
	case VersionNum::FUZZ:
	case VersionNum_Type_VersionNum_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
	case VersionNum_Type_VersionNum_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
		m_output << "\"" << _x.major() << "." << _x.minor() << "\"";
		break;
	}
}

void ProtoConverter::visit(Encodings const& _x)
{
	if (!Encodings::Enc_IsValid(_x.name()))
		return;

	m_output << " encoding=\"";
	switch (_x.name())
	{
	case Encodings::BIG5:
		m_output << "BIG5";
		break;
	case Encodings::EUCJP:
		m_output << "EUC-JP";
		break;
	case Encodings::EUCKR:
		m_output << "EUC-KR";
		break;
	case Encodings::GB18030:
		m_output << "GB18030";
		break;
	case Encodings::ISO2022JP:
		m_output << "ISO-2022-JP";
		break;
	case Encodings::ISO2022KR:
		m_output << "ISO-2022-KR";
		break;
	case Encodings::ISO88591:
		m_output << "ISO-8859-1";
		break;
	case Encodings::ISO88592:
		m_output << "ISO-8859-2";
		break;
	case Encodings::ISO88593:
		m_output << "ISO-8859-3";
		break;
	case Encodings::ISO88594:
		m_output << "ISO-8859-4";
		break;
	case Encodings::ISO88595:
		m_output << "ISO-8859-5";
		break;
	case Encodings::ISO88596:
		m_output << "ISO-8859-6";
		break;
	case Encodings::ISO88597:
		m_output << "ISO-8859-7";
		break;
	case Encodings::ISO88598:
		m_output << "ISO-8859-8";
		break;
	case Encodings::ISO88599:
		m_output << "ISO-8859-9";
		break;
	case Encodings::SHIFTJIS:
		m_output << "SHIFT_JIS";
		break;
	case Encodings::TIS620:
		m_output << "TIS-620";
		break;
	case Encodings::USASCII:
		m_output << "US-ASCII";
		break;
	case Encodings::UTF8:
		m_output << "UTF-8";
		break;
	case Encodings::UTF16:
		m_output << "UTF-16";
		break;
	case Encodings::UTF16BE:
		m_output << "UTF-16BE";
		break;
	case Encodings::UTF16LE:
		m_output << "UTF-16LE";
		break;
	case Encodings::WINDOWS31J:
		m_output << "WINDOWS-31J";
		break;
	case Encodings::WINDOWS1255:
		m_output << "WINDOWS-1255";
		break;
	case Encodings::WINDOWS1256:
		m_output << "WINDOWS-1256";
		break;
	case Encodings::FUZZ:
		m_output << removeNonAscii(_x.fuzz());
		break;
	case Encodings_Enc_Encodings_Enc_INT_MIN_SENTINEL_DO_NOT_USE_:
	case Encodings_Enc_Encodings_Enc_INT_MAX_SENTINEL_DO_NOT_USE_:
		break;
	}
	m_output << "\"";
}

void ProtoConverter::visit(XmlDeclaration const& _x)
{
	m_output << R"(<?xml version=)";
	visit(_x.ver());
	visit(_x.enc());
	switch (_x.standalone())
	{
	case XmlDeclaration::YES:
		m_output << " standalone=\'yes\'";
		break;
	case XmlDeclaration::NO:
		m_output << " standalone=\'no\'";
		break;
	case XmlDeclaration_Standalone_XmlDeclaration_Standalone_INT_MIN_SENTINEL_DO_NOT_USE_:
	case XmlDeclaration_Standalone_XmlDeclaration_Standalone_INT_MAX_SENTINEL_DO_NOT_USE_:
	default:
		break;
	}
	m_output << "?>\n";
}

void ProtoConverter::visit(XmlDocument const& _x)
{
	visit(_x.p());
	for (auto const& element: _x.e())
		visit(element);
}

string ProtoConverter::protoToString(XmlDocument const& _x)
{
	visit(_x);
	return m_output.str();
}
