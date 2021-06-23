#include "maldoca/service/common/process_doc.h"

#include <string>
#include <string_view>
#include "maldoca/service/proto/doc_type.pb.h"
#include "maldoca/service/proto/processing_config.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const string config_data = R"pb(
        handler_configs {
        key: "office_parser"
        value {
            doc_type: OFFICE
            parser_config {
            handler_type: DEFAULT_VBA_PARSER
            use_sandbox: false
            handler_config {
                default_office_parser_config {
                extract_vba_settings {
                    extraction_method: EXTRACTION_TYPE_LIGHTWEIGHT
                    allow_errors: true
                    run_for_all_files: true
                }
                }
            }
            }
        }
        })pb";

    ProcessorConfig processor_config;
    processor_config.ParseFromString(config_data);
    DocProcessor doc_processor = DocProcessor(processor_config);
    doc_processor.Init();

    ProcessDocumentRequest* process_doc_request;
    std::string_view file_name{ "document.docx" };
    std::string_view input = string_view(reinterpret_cast<const char *>(data), size);
    process_doc_request.set_file_name(file_name);
    process_doc_request.set_doc_content(input);

    ProcessDocumentRequest* document_response;

    ProcessDoc(file_name, doc, process_doc_request, document_response);

    return 0;

}