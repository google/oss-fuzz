#include "maldoca/service/common/process_doc.h"

#include <string>
#include <string_view>
#include "maldoca/service/proto/doc_type.pb.h"
#include "maldoca/service/proto/processing_config.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string config_data = R"pb(
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

    maldoca::ProcessorConfig processor_config;
    processor_config.ParseFromString(config_data);
    maldoca::DocProcessor doc_processor(processor_config);

    maldoca::ProcessDocumentRequest process_doc_request;
    const std::string file_name = "document.docx";
    const char *input = reinterpret_cast<const char *>(data);

    process_doc_request.set_file_name(file_name);
    process_doc_request.set_doc_content(input);

    maldoca::ProcessDocumentResponse document_response;

    doc_processor.ProcessDoc(&process_doc_request, &document_response);

    return 0;

}