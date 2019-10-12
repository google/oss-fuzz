#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "ops.pb.h"

#include <Magick++/Blob.h>
#include <Magick++/Image.h>
#include <Magick++/Functions.h>
#include <Magick++/ResourceLimits.h>
#include <Magick++/SecurityPolicy.h>

class FuzzingInitializer {
public:
  FuzzingInitializer() {

    // Disable SIMD in jpeg turbo.
    (void) putenv(const_cast<char *>("JSIMD_FORCENONE=1"));

    Magick::InitializeMagick((const char *) NULL);
    Magick::SecurityPolicy::anonymousCacheMemoryMap();
    Magick::SecurityPolicy::anonymousSystemMemoryMap();
    Magick::SecurityPolicy::maxMemoryRequest(256000000);
    Magick::ResourceLimits::memory(1000000000);
    Magick::ResourceLimits::map(500000000);
    Magick::ResourceLimits::width(2048);
    Magick::ResourceLimits::height(2048);
    Magick::ResourceLimits::listLength(16);
  }
};

FuzzingInitializer fuzzingInitializer;

Magick::AlphaChannelOption getAlphaChannelOption(const image_api_fuzzer::AlphaChannel& a) {
    switch (a.alpha()) {
        case image_api_fuzzer::AlphaChannel::Activate: {
            return Magick::AlphaChannelOption::ActivateAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Assosciate: {
            return Magick::AlphaChannelOption::AssociateAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Deactivate: {
            return Magick::AlphaChannelOption::DeactivateAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Disassociate: {
            return Magick::AlphaChannelOption::DisassociateAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Set: {
            return Magick::AlphaChannelOption::SetAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Opaque: {
            return Magick::AlphaChannelOption::OpaqueAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Transparent: {
            return Magick::AlphaChannelOption::TransparentAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Extract: {
            return Magick::AlphaChannelOption::ExtractAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Copy: {
            return Magick::AlphaChannelOption::CopyAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Shape: {
            return Magick::AlphaChannelOption::ShapeAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Remove: {
            return Magick::AlphaChannelOption::RemoveAlphaChannel;
        }
        case image_api_fuzzer::AlphaChannel::Background: {
            return Magick::AlphaChannelOption::BackgroundAlphaChannel;
        }
    }
}

DEFINE_BINARY_PROTO_FUZZER(const image_api_fuzzer::FuzzSession& fuzz_session) {
    if (fuzz_session.fuzz_operations().size() > 8) {
        return;
    }

    Magick::Image image;
    switch (fuzz_session.format()) {
        case image_api_fuzzer::FuzzSession::RLA: {
            image.magick("rla");
            image.fileName("rla:");
            break;
        }
    }
    const Magick::Blob blob(fuzz_session.image_data().data(), fuzz_session.image_data().size());
    try {
        image.read(blob);

        for (const image_api_fuzzer::FuzzOperation op : fuzz_session.fuzz_operations()) {
            switch (op.operation_case()) {
                case image_api_fuzzer::FuzzOperation::kAlphaChannel: {
                    image.alphaChannel(getAlphaChannelOption(op.alpha_channel()));
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kBlur: {
                    image.blur(op.blur().radius(), op.blur().sigma());
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kContrast: {
                    image.contrast(op.contrast().sharpen());
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kDespeckle: {
                    image.despeckle();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kEnhance: {
                    image.enhance();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kEqualize: {
                    image.equalize();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kErase: {
                    image.erase();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kFlip: {
                    image.flip();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kFlop: {
                    image.flop();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kImplode: {
                    image.implode(op.implode().factor());
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kMagnify: {
                    image.magnify();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kMinify: {
                    image.minify();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kMonochrome: {
                    image.monochrome(op.monochrome().monochrome());
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kNormalize: {
                    image.normalize();
                    break;
                }
                case image_api_fuzzer::FuzzOperation::kTrim: {
                    image.trim();
                    break;
                }
            }
        }
        Magick::Blob outBlob;
        image.write(&outBlob, "BMP");
    } catch (Magick::Exception& e) {
    }
}