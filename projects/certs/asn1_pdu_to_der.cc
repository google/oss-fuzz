#include "asn1_pdu_to_der.h"

namespace asn1_pdu {

// The maximum level of recursion allowed. Values greater than this will just
// fail.
static constexpr size_t kRecursionLimit = 200;

void ASN1PDUToDER::EncodeOverrideLength(const std::string& raw_len,
                                        const size_t len_pos) {
  der_.insert(der_.begin() + len_pos, raw_len.begin(), raw_len.end());
}

void ASN1PDUToDER::EncodeIndefiniteLength(const size_t len_pos) {
  der_.insert(der_.begin() + len_pos, 0x80);
  // The PDU's value is from |len_pos| to the end of |der_|, so just add an
  // EOC marker to the end.
  der_.push_back(0x00);
  der_.push_back(0x00);
}

void ASN1PDUToDER::EncodeDefiniteLength(const size_t actual_len,
                                        const size_t len_pos) {
  InsertVariableInt(actual_len, len_pos, der_);
  // X.690 (2015), 8.1.3.3: The long-form is used when the length is
  // larger than 127.
  // Note: |len_num_bytes| is not checked here, because it will equal
  // 1 for values [128..255], but those require the long-form length.
  if (actual_len > 127) {
    // See X.690 (2015) 8.1.3.5.
    // Long-form length is encoded as a byte with the high-bit set to indicate
    // the long-form, while the remaining bits indicate how many bytes are used
    // to encode the length.
    size_t len_num_bytes = GetVariableIntLen(actual_len, 256);
    der_.insert(der_.begin() + len_pos, (0x80 | len_num_bytes));
  }
}

void ASN1PDUToDER::EncodeLength(const Length& len,
                                const size_t actual_len,
                                const size_t len_pos) {
//   if (len.has_length_override()) {
//     EncodeOverrideLength(len.length_override(), len_pos);
//   } else if (len.has_indefinite_form() && len.indefinite_form()) {
//     EncodeIndefiniteLength(len_pos);
//   } else {
//     EncodeDefiniteLength(actual_len, len_pos);
//   }
  EncodeDefiniteLength(actual_len, len_pos);
}

void ASN1PDUToDER::EncodeValue(const Value& val) {
  for (const auto& val_ele : val.val_array()) {
    if (recursion_exceeded_) {
      // If the message exceeds the recursion limit, abort processing the
      // protobuf in order to limit uninteresting work.
      return;
    }
    if (val_ele.has_pdu()) {
      EncodePDU(val_ele.pdu());
    } else {
      der_.insert(der_.end(), val_ele.val_bits().begin(),
                  val_ele.val_bits().end());
    }
  }
}

void ASN1PDUToDER::EncodeHighTagNumberForm(const uint8_t id_class,
                                           const uint8_t encoding,
                                           const uint32_t tag_num) {
  // The high-tag-number form base 128 encodes |tag_num| (X.690 (2015), 8.1.2).
  uint8_t num_bytes = GetVariableIntLen(tag_num, 128);
  // High-tag-number form requires the lower 5 bits of the identifier to be set
  // to 1 (X.690 (2015), 8.1.2.4.1).
  uint64_t id_parsed = (id_class | encoding | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = num_bytes - 1; i != 0; --i) {
    // If it's not the last byte, the high bit is set to 1 (X.690
    // (2015), 8.1.2.4.2).
    id_parsed |= ((0x01 << 7) | ((tag_num >> (i * 7)) & 0x7F));
    id_parsed <<= 8;
  }
  id_parsed |= (tag_num & 0x7F);
  InsertVariableInt(id_parsed, der_.size(), der_);
}

void ASN1PDUToDER::EncodeIdentifier(const Identifier& id) {
  // The class comprises the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding comprises the 6th bit of the identifier (X.690 (2015), 8.1.2).
  uint8_t encoding = static_cast<uint8_t>(id.encoding()) << 5;

  uint32_t tag_num = id.tag_num().has_high_tag_num()
                         ? id.tag_num().high_tag_num()
                         : id.tag_num().low_tag_num();
  if(tag_num == 0) {
      tag_num = 129;
  }
  // When the tag number is greater than or equal to 31, encode with a single
  // byte; otherwise, use the high-tag-number form (X.690 (2015), 8.1.2).
  if (tag_num >= 31) {
    EncodeHighTagNumberForm(id_class, encoding, tag_num);
  } else {
    der_.push_back(static_cast<uint8_t>(id_class | encoding | tag_num));
  }
}

void ASN1PDUToDER::EncodePDU(const PDU& pdu) {
  // Artifically limit the stack depth to avoid stack overflow.
  if (depth_ > kRecursionLimit) {
    recursion_exceeded_ = true;
    return;
  }
  ++depth_;
  EncodeIdentifier(pdu.id());
  size_t len_pos = der_.size();
  EncodeValue(pdu.val());
  EncodeLength(pdu.len(), der_.size() - len_pos, len_pos);
  --depth_;
}

std::vector<uint8_t> ASN1PDUToDER::PDUToDER(const PDU& pdu) {
  // Reset the previous state.
  der_.clear();
  depth_ = 0;
  recursion_exceeded_ = false;

  EncodePDU(pdu);
  if (recursion_exceeded_) {
    der_.clear();
  }
  return der_;
}

}  // namespace asn1_pdu