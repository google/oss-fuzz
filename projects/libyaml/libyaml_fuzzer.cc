#include <stdint.h>

#include <yaml.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    yaml_parser_t parser;
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, data, size);

    int done = 0;
    while (!done) {
        yaml_event_t event;
        if (!yaml_parser_parse(&parser, &event)) {
            break;
        }
        done = (event.type == YAML_STREAM_END_EVENT);
        yaml_event_delete(&event);
    }
    yaml_parser_delete(&parser);
    return 0;
}
