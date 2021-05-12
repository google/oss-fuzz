/*
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include "processor/module_comparer.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <string>

#include "processor/basic_source_line_resolver_types.h"
#include "processor/basic_code_module.h"


namespace {

using google_breakpad::SourceLineResolverBase;
using google_breakpad::BasicSourceLineResolver;
using google_breakpad::FastSourceLineResolver;
using google_breakpad::ModuleSerializer;
using google_breakpad::ModuleComparer;
using google_breakpad::CFIFrameInfo;
using google_breakpad::CodeModule;
using google_breakpad::MemoryRegion;
using google_breakpad::StackFrame;
using google_breakpad::WindowsFrameInfo;
using google_breakpad::linked_ptr;
using google_breakpad::scoped_ptr;

class TestCodeModule : public CodeModule {
 public:
  explicit TestCodeModule(string code_file) : code_file_(code_file) {}
  virtual ~TestCodeModule() {}

  virtual uint64_t base_address() const { return 0; }
  virtual uint64_t size() const { return 0xb000; }
  virtual string code_file() const { return code_file_; }
  virtual string code_identifier() const { return ""; }
  virtual string debug_file() const { return ""; }
  virtual string debug_identifier() const { return ""; }
  virtual string version() const { return ""; }
  virtual CodeModule* Copy() const {
    return new TestCodeModule(code_file_);
  }
  virtual bool is_unloaded() const { return false; }
  virtual uint64_t shrink_down_delta() const { return 0; }
  virtual void SetShrinkDownDelta(uint64_t shrink_down_delta) {}

 private:
  string code_file_;
};

void load_module(const uint8_t *data, size_t size) {
	char filename[256];
	sprintf(filename, "/tmp/libfuzzer");

	FILE *fp = fopen(filename, "wb");
	if (!fp)
		return;
	fwrite(data, size, 1, fp);
	fclose(fp);
	google_breakpad::BasicSourceLineResolver resolver;
	TestCodeModule module1("module1");
	resolver.LoadModule(&module1, filename);
	std::remove(filename);
}

} // namespace


extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){	
	load_module(data, size);	
	return 0;
}
