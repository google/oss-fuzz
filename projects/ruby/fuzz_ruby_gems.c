/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "init_ruby_load_paths.h"
#include <ruby/ruby.h>
#include <unistd.h>

#define ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))

// The maximum number of arguments of any of the target functions.
// Increase as needed.
#define MAX_NARGS 2

enum RubyDataType { RDT_CString };

struct TargetFunction {
  const char *module_;
  const char *cls_;
  const char *name_;
  VALUE module_obj_;
  VALUE cls_obj_;
  ID method_id_;
  int nargs_;
  const enum RubyDataType *argTypes_;
};

struct TargetCall {
  struct TargetFunction *fcn_;
  VALUE *args_;
};

VALUE eval(const char *cmd) {
  int state = 0;
  VALUE result = rb_eval_string_protect(cmd, &state);
  if (state != 0) {
    rb_set_errinfo(Qnil);
  }

  return result;
}

static VALUE call_protected_helper(VALUE rdata) {
  struct TargetCall *call = (struct TargetCall *)(rdata);
  struct TargetFunction *fcn = call->fcn_;
  return rb_funcall2(fcn->cls_obj_, fcn->method_id_, fcn->nargs_, call->args_);
};

VALUE call_protected(struct TargetCall *call) {
  int state = 0;
  VALUE result = rb_protect(call_protected_helper, (VALUE)(call), &state);
  if (state != 0) {
    rb_set_errinfo(Qnil);
  }
  return result;
}

VALUE require(const char *module) {
  int state = 0;
  VALUE result =
      rb_protect(RUBY_METHOD_FUNC(rb_require), (VALUE)module, &state);
  if (state != 0) {
    rb_set_errinfo(Qnil);
  }
  return result;
}

struct ByteStream {
  const uint8_t *data_;
  size_t size_;
  size_t pos_;
};

void ByteStream_init(struct ByteStream *bs, const uint8_t *data, size_t size) {
  bs->data_ = data;
  bs->size_ = size;
  bs->pos_ = 0;
}

// Copy bytes from the ByteStream into `data`. Returns 0 on success, -1 on
// error. Error only occurs if there aren't enough bytes remaining in the
// ByteStream.
int ByteStream_get_bytes(struct ByteStream *bs, uint8_t *data, size_t size) {
  if (size > bs->size_ - bs->pos_) {
    return -1;
  }
  memcpy(data, bs->data_ + bs->pos_, size);
  bs->pos_ += size;
  return 0;
}

// Initialize x with bytes from the ByteStream. Returns -1 on error.
int BytesStream_get_uint32_t(struct ByteStream *bs, uint32_t *x) {
  return ByteStream_get_bytes(bs, (uint8_t *)x, sizeof(*x));
}

// Initialize x with bytes from the ByteStream. Returns -1 on error.
int BytesStream_get_uint64_t(struct ByteStream *bs, uint64_t *x) {
  return ByteStream_get_bytes(bs, (uint8_t *)x, sizeof(*x));
}

VALUE generate_CString(struct ByteStream *bs) {
  uint64_t size = 0;
  if (BytesStream_get_uint64_t(bs, &size) < 0) {
    return 0;
  }
  if (size > (unsigned long)LONG_MAX) {
    return 0;
  }
  if (size > bs->size_ - bs->pos_) {
    //    return 0;
    size = bs->size_ - bs->pos_;
  }
  char *data = malloc(size);
  if (!data) {
    return 0;
  }
  VALUE result = 0;
  if (ByteStream_get_bytes(bs, (uint8_t *)data, size) < 0) {
    goto out;
  }
  result = rb_str_new(data, (long)size);

out:
  free(data);
  return result;
}

VALUE generate_value(struct ByteStream *bs, const enum RubyDataType t) {
  switch (t) {
  case RDT_CString:
    return generate_CString(bs);
  default:
    return 0;
  }
}

int run_fuzz_function(struct ByteStream *bs, struct TargetFunction *fcn) {
  if (fcn->nargs_ < 0) {
    return -1;
  }

  VALUE args[MAX_NARGS] = {};
  int result = -1;
  int i;
  assert(fcn->nargs_ <= MAX_NARGS);
  for (i = 0; i < fcn->nargs_; i++) {
    VALUE v = generate_value(bs, fcn->argTypes_[i]);
    if (!v) {
      goto out;
    }
    args[i] = v;
  }

  struct TargetCall call;
  call.fcn_ = fcn;
  call.args_ = args;

  if (call_protected(&call)) {
    result = 0;
  }

out:
  return result;
}

void init_TargetFunction(struct TargetFunction *target, const char *module,
                         const char *cls, const char *name, const int nargs,
                         const enum RubyDataType *argTypes) {
  target->module_ = module;
  target->module_obj_ = require(module);
  rb_global_variable(&target->module_obj_);
  target->cls_ = cls;
  target->cls_obj_ = rb_path2class(cls);
  rb_global_variable(&target->cls_obj_);
  target->name_ = name;
  target->method_id_ = rb_intern(name);
  target->nargs_ = nargs;
  target->argTypes_ = argTypes;
}

static void init_date_strptime(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[2] = {RDT_CString, RDT_CString};
  init_TargetFunction(target, "date", "Date", "strptime", ARRAYSIZE(argTypes),
                      argTypes);
}

static void init_date_httpdate(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "date", "Date", "httpdate", ARRAYSIZE(argTypes),
                      argTypes);
}

static void init_date_parse(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "date", "Date", "parse", ARRAYSIZE(argTypes),
                      argTypes);
}

static void init_regexp_new(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "regexp", "Regexp", "new",
                      ARRAYSIZE(argTypes), argTypes);
}

static void init_json_parse(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "json", "JSON", "parse", ARRAYSIZE(argTypes),
                      argTypes);
}

static void init_psych_parse(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "psych", "Psych", "parse", ARRAYSIZE(argTypes),
                      argTypes);
}

static void init_openssl_read(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "openssl", "OpenSSL::PKey", "read",
                      ARRAYSIZE(argTypes), argTypes);
}

static void init_openssl_read_smime(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "openssl", "OpenSSL::PKCS7", "read_smime",
                      ARRAYSIZE(argTypes), argTypes);
}

static void init_openssl_sprintf(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[2] = {RDT_CString, RDT_CString};
  init_TargetFunction(target, "openssl", "Kernel", "sprintf",
                      ARRAYSIZE(argTypes), argTypes);
}

static void init_CGI_unescapeHTML(struct TargetFunction *target) {
  static const enum RubyDataType argTypes[1] = {RDT_CString};
  init_TargetFunction(target, "cgi", "CGI", "unescapeHTML", ARRAYSIZE(argTypes),
                      argTypes);
}

typedef void (*init_TargetFunction_ptr)(struct TargetFunction *target);

static init_TargetFunction_ptr init_functions[] = {
    init_date_parse,         init_date_strptime,   init_date_httpdate,
    init_json_parse,         init_psych_parse,     init_openssl_read,
    init_openssl_read_smime, init_openssl_sprintf, init_CGI_unescapeHTML,
    init_regexp_new };

// setenv("RUBYLIB", ...) so that dynamic loading of ruby gems
// (which are in an unusual location due to the OSS-Fuzz infrastructure)
// will work.
static int setenv_rubylib() {
  char rubylib[0x1000];
  char exepath[PATH_MAX];

  // Deduce the location of the OUT directory from the executable path.
  ssize_t n = readlink("/proc/self/exe", exepath, sizeof(exepath));

  // Find the parent directory.
  do {
    if (n <= 0) {
      return -1;
    }
  } while(exepath[--n] != '/');
  exepath[n] = '\0';
  fprintf(stderr, "exepath = %s\n", exepath);

  // init_ruby_load_paths() is automatically generated by build.sh
  const int r = init_ruby_load_paths(rubylib, sizeof(rubylib), exepath);
  if (r < 0 || (size_t)r >= sizeof(rubylib)) {
    return -1;
  }
  fprintf(stderr, "RUBYLIB = %s\n", rubylib);
  if (setenv("RUBYLIB", rubylib, 1) < 0) {
    return -1;
  }
  return 0;
}

// Bogus code to add a bunch of extra calls to __ubsan functions so that we
// get over the minimum threshold (169 calls) required by bad_build_check:
// https://github.com/google/oss-fuzz/blob/5af82b8e388a3455690c40d3d99c92d4a213a602/infra/base-images/base-runner/bad_build_check#L44-L48
static void workaround_UBSAN_CALLS_THRESHOLD_FOR_UBSAN_BUILD(size_t x) {
  static size_t n = 0;
  switch (x) {
  case 0:
    n++;
  case 1:
    n++;
  case 2:
    n++;
  case 3:
    n++;
  case 4:
    n++;
  case 5:
    n++;
  case 6:
    n++;
  case 7:
    n++;
  case 8:
    n++;
  case 9:
    n++;
  case 10:
    n++;
  case 11:
    n++;
  case 12:
    n++;
  case 13:
    n++;
  case 14:
    n++;
  case 15:
    n++;
  case 16:
    n++;
  case 17:
    n++;
  case 18:
    n++;
  case 19:
    n++;
  case 20:
    n++;
  case 21:
    n++;
  case 22:
    n++;
  case 23:
    n++;
  case 24:
    n++;
  case 25:
    n++;
  case 26:
    n++;
  case 27:
    n++;
  case 28:
    n++;
  case 29:
    n++;
  case 30:
    n++;
  case 31:
    n++;
  case 32:
    n++;
  case 33:
    n++;
  case 34:
    n++;
  case 35:
    n++;
  case 36:
    n++;
  case 37:
    n++;
  case 38:
    n++;
  case 39:
    n++;
  default:
    n++;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ByteStream bs = {};

  ByteStream_init(&bs, data, size);

  // Static array of target functions. These only need to be initialized once.
  static struct TargetFunction target_functions[ARRAYSIZE(init_functions)] = {};

  // Initialize the Ruby interpreter.
  static bool ruby_initialized = false;
  if (!ruby_initialized) {
    ruby_initialized = true;

    if (setenv_rubylib() < 0) {
      abort();
    }

    ruby_init();
    ruby_init_loadpath();

    // Initialize the fuzzing functions.
    for (size_t i = 0; i < ARRAYSIZE(init_functions); i++) {
      init_functions[i](&target_functions[i]);
    }

    uint32_t x = 0;
    BytesStream_get_uint32_t(&bs, &x);
    workaround_UBSAN_CALLS_THRESHOLD_FOR_UBSAN_BUILD(x);

    // Reset the byte stream
    ByteStream_init(&bs, data, size);
  }

  // Choose a function from `target_functions`.
  uint32_t i = 0;
  if (BytesStream_get_uint32_t(&bs, &i) < 0) {
    goto out;
  }
  struct TargetFunction *fcn =
      &target_functions[i % ARRAYSIZE(target_functions)];
  run_fuzz_function(&bs, fcn);

out:
  return 0;
}
