#ifndef ASN1_UNIVERSAL_TYPES_TO_DER_H_
#define ASN1_UNIVERSAL_TYPES_TO_DER_H_

#include <google/protobuf/util/time_util.h>
#include <stdint.h>

#include <vector>

#include "asn1_universal_types.pb.h"
#include "common.h"

namespace asn1_universal_types {

// DER encodes |bit_string| according to X.690 (2015), 8.6.
// Appends encoded |bit_string| to |der|.
void Encode(const BitString& bit_string, std::vector<uint8_t>& der);

// DER encodes |integer| according to X.690 (2015), 8.3.
// Appends encoded |integer| to |der|.
void Encode(const Integer& integer, std::vector<uint8_t>& der);

// DER encodes |utc_time| according to X.690 (2015), 11.8.
// Appends encoded |utc_time| to |der|.
void Encode(const UTCTime& utc_time, std::vector<uint8_t>& der);

// DER encodes |generalized_time| according to X.690 (2015), 11.7.
// Appends encoded |generalized_time| to |der|.
void Encode(const GeneralizedTime& generalized_time, std::vector<uint8_t>& der);

// DER encodes |time_stamp| where |num_fields| determines which type of ASN.1
// TIME type is encoded.
// Appends encoded |time_stamp| to |der|.
void Encode(const google::protobuf::Timestamp& time_stamp,
            const uint8_t num_fields,
            std::vector<uint8_t>& der);

}  // namespace asn1_universal_types

#endif