// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "Poco/MemoryStream.h"
#include "Poco/Net/MailMessage.h"
#include "Poco/Net/MailStream.h"
#include "Poco/NullStream.h"

using namespace Poco;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    MemoryInputStream stream(reinterpret_cast<const char *>(data), size);
    Net::MailInputStream mis(stream);
    Net::MailMessage mail;
    mail.read(mis);
    mail.addRecipient(
        Net::MailRecipient(Net::MailRecipient::CC_RECIPIENT,
                           Net::MailMessage::encodeWord(mail.getSender())));
    NullOutputStream null;
    Net::MailOutputStream mos(null);
    mail.write(mos);
  } catch (const std::exception &) {
  }

  return 0;
}
