#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "tinyxml2/tinyxml2.h"

using namespace tinyxml2;

void fuzz_parse_xml(const uint8_t* data, size_t size) {
    std::string xml(reinterpret_cast<const char*>(data), size);
    XMLDocument doc;
    doc.Parse(xml.c_str(), size);

    XMLElement* root = doc.RootElement();
    if (root) {
        root->Name();
        root->GetText();
        root->GetDocument();

        for (const XMLAttribute* attr = root->FirstAttribute(); attr; attr = attr->Next()) {
            attr->Name();
            attr->Value();
        }

        for (XMLElement* child = root->FirstChildElement(); child; child = child->NextSiblingElement()) {
            child->Name();
        }
    }

    doc.Print();
    doc.Clear();
}

void fuzz_create_dom(const uint8_t* data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), size);

    XMLDocument doc;
    XMLElement* root = doc.NewElement("root");
    doc.InsertFirstChild(root);

    XMLElement* child = doc.NewElement("child");
    child->SetAttribute("id", 123);              // May invoke unsafe behavior
    child->SetText(text.c_str());                // Direct pass without checking
    root->InsertEndChild(child);

    doc.SaveFile("/dev/null");
    doc.Clear();
}

void fuzz_api_surface(const uint8_t* data, size_t size) {
    XMLDocument doc;
    XMLNode* decl = doc.NewDeclaration();
    doc.InsertFirstChild(decl);

    XMLUnknown* unknown = doc.NewUnknown("<!-- fuzz -->");
    doc.InsertEndChild(unknown);

    XMLText* textNode = doc.NewText("FuzzTest");
    doc.InsertEndChild(textNode);

    doc.ErrorID();
    doc.ErrorStr();
}

void fuzz_error_classification() {
    for (int i = 0; i < 100; ++i) {
        const char* name = XMLDocument::ErrorIDToName(static_cast<XMLError>(i));
        std::string s(name); // no null check
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzz_parse_xml(data, size);
    fuzz_create_dom(data, size);
    fuzz_api_surface(data, size);
    fuzz_error_classification();
    return 0;
}