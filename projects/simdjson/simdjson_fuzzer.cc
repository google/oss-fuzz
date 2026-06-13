#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "simdjson.h"

// Fuzz the simdjson JSON parser (DOM and On-Demand APIs).
// Exercises: padding, parsing, type dispatch, recursive value
// traversal, and error handling through both APIs.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // --- DOM API ---
    {
        simdjson::dom::parser parser;
        simdjson::dom::element doc;
        // padded_string copies and pads the input.
        simdjson::padded_string padded(
            reinterpret_cast<const char *>(data), size);
        auto err = parser.parse(padded).get(doc);
        if (!err) {
            // Traverse the top-level value.
            if (doc.is_object()) {
                for (auto [key, val] : doc.get_object()) {
                    (void)key;
                    (void)val.type();
                }
            } else if (doc.is_array()) {
                for (auto val : doc.get_array()) {
                    (void)val.type();
                }
            }
        }
    }

    // --- On-Demand API ---
    {
        simdjson::ondemand::parser parser;
        simdjson::padded_string padded(
            reinterpret_cast<const char *>(data), size);
        simdjson::ondemand::document doc;
        auto err = parser.iterate(padded).get(doc);
        if (!err) {
            simdjson::ondemand::json_type type;
            if (!doc.type().get(type)) {
                switch (type) {
                case simdjson::ondemand::json_type::object: {
                    simdjson::ondemand::object obj;
                    if (!doc.get_object().get(obj)) {
                        for (auto field : obj) {
                            (void)field.key();
                        }
                    }
                    break;
                }
                case simdjson::ondemand::json_type::array: {
                    simdjson::ondemand::array arr;
                    if (!doc.get_array().get(arr)) {
                        for (auto val : arr) {
                            (void)val.type();
                        }
                    }
                    break;
                }
                default:
                    break;
                }
            }
        }
    }

    return 0;
}
