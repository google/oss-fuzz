#include "tinyxml2/tinyxml2.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace tinyxml2;

struct ByteReader {
    const uint8_t *p;
    const uint8_t *end;

    explicit ByteReader(const uint8_t *d, size_t s) : p(d), end(d + s) {}

    bool empty() const { return p >= end; }
    uint8_t u8()  { return empty() ? 0 : *p++; }
    uint32_t u32() {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | u8();
        return v;
    }
    std::string str(size_t maxLen = 64) {
        size_t avail = (size_t)(end - p);
        size_t take  = avail < maxLen ? avail : maxLen;
        std::string s(reinterpret_cast<const char *>(p), take);
        p += take;
        return s;
    }
};

static void ExerciseAttributeAndTextQueries(const XMLElement *elem) {
    if (!elem) return;

    for (const XMLAttribute *a = elem->FirstAttribute(); a; a = a->Next()) {
        int       iv  = 0;
        unsigned  uv  = 0;
        int64_t   i64 = 0;
        uint64_t  u64 = 0;
        bool      bv  = false;
        double    dv  = 0.0;
        float     fv  = 0.0f;

        a->QueryIntValue(&iv);
        a->QueryUnsignedValue(&uv);
        a->QueryInt64Value(&i64);
        a->QueryUnsigned64Value(&u64);
        a->QueryBoolValue(&bv);
        a->QueryDoubleValue(&dv);
        a->QueryFloatValue(&fv);

        elem->IntAttribute(a->Name(), 0);
        elem->UnsignedAttribute(a->Name(), 0U);
        elem->Int64Attribute(a->Name(), 0LL);
        elem->Unsigned64Attribute(a->Name(), 0ULL);
        elem->BoolAttribute(a->Name(), false);
        elem->DoubleAttribute(a->Name(), 0.0);
        elem->FloatAttribute(a->Name(), 0.0f);
    }

    {
        int       iv  = 0;
        unsigned  uv  = 0;
        int64_t   i64 = 0;
        uint64_t  u64 = 0;
        bool      bv  = false;
        double    dv  = 0.0;
        float     fv  = 0.0f;

        elem->QueryIntText(&iv);
        elem->QueryUnsignedText(&uv);
        elem->QueryInt64Text(&i64);
        elem->QueryUnsigned64Text(&u64);
        elem->QueryBoolText(&bv);
        elem->QueryDoubleText(&dv);
        elem->QueryFloatText(&fv);

        elem->IntText(0);
        elem->UnsignedText(0U);
        elem->Int64Text(0LL);
        elem->Unsigned64Text(0ULL);
        elem->BoolText(false);
        elem->DoubleText(0.0);
        elem->FloatText(0.0f);
        elem->GetText();
    }

    elem->ChildElementCount();
    elem->ChildElementCount(elem->Name());

    for (const XMLElement *c = elem->FirstChildElement(); c; c = c->NextSiblingElement())
        ExerciseAttributeAndTextQueries(c);
}

static void ParseAndQuery(const uint8_t *data, size_t size) {
    static const Whitespace kModes[] = {
        PRESERVE_WHITESPACE,
        COLLAPSE_WHITESPACE,
        PEDANTIC_WHITESPACE
    };
    for (int mi = 0; mi < 3; ++mi) {
        for (int pe = 0; pe < 2; ++pe) {
            bool procEntities = (pe == 0);
            XMLDocument doc(procEntities, kModes[mi]);
            if (doc.Parse(reinterpret_cast<const char *>(data), size) != XML_SUCCESS)
                continue;

            ExerciseAttributeAndTextQueries(doc.RootElement());

            XMLPrinter printer;
            doc.Print(&printer);
            const char *printed = printer.CStr();

            if (printed && printer.CStrSize() > 1) {
                XMLDocument doc2;
                doc2.Parse(printed);
            }
        }
    }
}

static void FuzzNumericCharRefs(const uint8_t *data, size_t size) {
    if (size < 4) return;

    ByteReader r(data, size);
    uint32_t codepoint = r.u32() & 0x1FFFFF;
    bool useHex = (r.u8() & 1) != 0;

    char xmlbuf[128];

    if (useHex)
        snprintf(xmlbuf, sizeof(xmlbuf), "<r>&#x%X;</r>", (unsigned)codepoint);
    else
        snprintf(xmlbuf, sizeof(xmlbuf), "<r>&#%u;</r>", (unsigned)codepoint);

    XMLDocument doc;
    if (doc.Parse(xmlbuf) == XML_SUCCESS) {
        const XMLElement *root = doc.RootElement();
        if (root) root->GetText();
    }

    if (useHex)
        snprintf(xmlbuf, sizeof(xmlbuf), "<r a=\"&#x%X;\"/>", (unsigned)codepoint);
    else
        snprintf(xmlbuf, sizeof(xmlbuf), "<r a=\"&#%u;\"/>", (unsigned)codepoint);

    XMLDocument doc2;
    if (doc2.Parse(xmlbuf) == XML_SUCCESS) {
        const XMLElement *root = doc2.RootElement();
        if (root) root->Attribute("a");
    }

    snprintf(xmlbuf, sizeof(xmlbuf), "<r>&#%u</r>", (unsigned)codepoint);
    XMLDocument doc3;
    doc3.Parse(xmlbuf);

    snprintf(xmlbuf, sizeof(xmlbuf), "<r>&#x%X</r>", (unsigned)codepoint);
    XMLDocument doc4;
    doc4.Parse(xmlbuf);
}

static void MutateDocumentTree(const uint8_t *data, size_t size) {
    ByteReader r(data, size);

    XMLDocument doc;
    XMLElement *root = doc.NewElement("root");
    if (!root) return;
    doc.InsertEndChild(root);

    std::string tagName  = r.str(16);
    std::string attrName = r.str(16);
    std::string textVal  = r.str(32);
    if (tagName.empty())  tagName  = "child";
    if (attrName.empty()) attrName = "attr";

    XMLElement     *child1 = doc.NewElement(tagName.c_str());
    XMLElement     *child2 = doc.NewElement("sibling");
    XMLComment     *cmt    = doc.NewComment("fuzz comment");
    XMLText        *txt    = doc.NewText(textVal.c_str());
    XMLDeclaration *decl   = doc.NewDeclaration(NULL);
    XMLUnknown     *unk    = doc.NewUnknown("!DOCTYPE fuzz");
    (void)decl;

    root->InsertEndChild(child1);
    root->InsertFirstChild(child2);
    if (child2) root->InsertAfterChild(child2, txt);
    XMLElement *child3 = root->InsertNewChildElement("inserted");

    if (child1) {
        child1->SetAttribute(attrName.c_str(), textVal.c_str());
        child1->SetAttribute("int_attr",    (int)r.u32());
        child1->SetAttribute("uint_attr",   (unsigned)r.u32());
        child1->SetAttribute("bool_attr",   (bool)(r.u8() & 1));
        child1->SetAttribute("double_attr", (double)(int32_t)r.u32() / 1000.0);
        child1->SetAttribute("float_attr",  (float)(int16_t)(r.u32() & 0xFFFF) / 100.0f);
        int64_t  i64v = ((int64_t)r.u32() << 32) | (int64_t)r.u32();
        uint64_t u64v = ((uint64_t)r.u32() << 32) | (uint64_t)r.u32();
        child1->SetAttribute("i64_attr", i64v);
        child1->SetAttribute("u64_attr", u64v);

        child1->SetText(textVal.c_str());
        child1->SetText((int)r.u32());
        child1->SetText((unsigned)r.u32());
        child1->SetText((bool)(r.u8() & 1));
        child1->SetText((double)(int32_t)r.u32() / 1e4);
        child1->SetText((float)(int16_t)(r.u32() & 0xFFFF) / 1e2f);
        child1->SetText(((int64_t)r.u32() << 32)  | (int64_t)r.u32());
        child1->SetText(((uint64_t)r.u32() << 32) | (uint64_t)r.u32());

        ExerciseAttributeAndTextQueries(child1);

        child1->DeleteAttribute(attrName.c_str());
        child1->DeleteAttribute("int_attr");
    }

    if (child2) {
        std::string newName = r.str(8);
        if (!newName.empty())
            child2->SetName(newName.c_str());
    }

    doc.InsertFirstChild(cmt);
    doc.InsertEndChild(unk);

    {
        XMLPrinter printer;
        doc.Print(&printer);
        doc.SaveFile("/dev/null", false);
        doc.SaveFile("/dev/null", true);
    }

    {
        XMLDocument copy;
        doc.DeepCopy(&copy);
        ExerciseAttributeAndTextQueries(copy.RootElement());
        XMLPrinter cp;
        copy.Print(&cp);
    }

    if (child3) root->DeleteChild(child3);

    doc.Clear();
    {
        XMLPrinter p2;
        doc.Print(&p2);
    }
}

static void CloneAndHandleTraversal(const uint8_t *data, size_t size) {
    if (size < 2) return;
    ByteReader r(data, size);

    std::string val1 = r.str(16);
    std::string val2 = r.str(16);

    XMLDocument doc;
    XMLElement *root  = doc.NewElement("root");
    XMLElement *child = doc.NewElement("child");
    if (!root || !child) return;

    doc.InsertEndChild(root);

    root->SetAttribute("a", val1.c_str());
    root->SetAttribute("a", val2.c_str());
    root->SetAttribute("b", "v");
    root->InsertEndChild(child);
    child->SetAttribute("b", "v");
    child->SetText("hello");

    {
        XMLDocument doc2;
        XMLNode *shallow = root->ShallowClone(&doc2);
        if (shallow) {
            root->ShallowEqual(shallow);
            XMLElement *diff = doc2.NewElement("other");
            if (diff) root->ShallowEqual(diff);
        }
    }

    {
        XMLDocument doc3;
        XMLNode *deep = root->DeepClone(&doc3);
        if (deep) {
            root->ShallowEqual(deep);
            ExerciseAttributeAndTextQueries(doc3.RootElement());
            XMLPrinter dp;
            doc3.Print(&dp);
        }
    }

    {
        XMLHandle h(&doc);
        XMLElement *e = h.FirstChildElement("root")
                         .FirstChildElement("child")
                         .ToElement();
        if (e) {
            e->Attribute("b");
            e->IntAttribute("b", -1);
        }

        XMLHandle hroot = h.FirstChildElement("root");
        XMLNode *n = hroot.ToNode();
        if (n) {
            XMLHandle hn(n);
            hn.FirstChild().ToNode();
            hn.LastChild().ToNode();
        }
    }

    {
        XMLConstHandle ch(static_cast<const XMLDocument &>(doc));
        const XMLElement *ce = ch.FirstChildElement("root")
                                 .FirstChildElement("child")
                                 .ToElement();
        if (ce) {
            ce->GetText();
            ce->Attribute("b");
        }
        const XMLNode *cn = ch.FirstChildElement("root").ToNode();
        if (cn) {
            XMLConstHandle hcn(cn);
            hcn.FirstChild().ToNode();
            hcn.LastChild().ToNode();
        }
    }

    {
        XMLPrinter pr;
        doc.Print(&pr);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    const uint8_t  selector = data[0] % 4;
    const uint8_t *payload  = data + 1;
    const size_t   psize    = size - 1;

    switch (selector) {
        case 0: ParseAndQuery(payload, psize);          break;
        case 1: FuzzNumericCharRefs(payload, psize);     break;
        case 2: MutateDocumentTree(payload, psize);      break;
        case 3: CloneAndHandleTraversal(payload, psize); break;
    }

    return 0;
}