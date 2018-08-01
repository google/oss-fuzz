#include <git2.h>
#include <git2/sys/transport.h>

#include <cstring>
#include <cstdlib>
#include <sys/stat.h>

#include <string>

struct fuzz_buffer {
    const uint8_t *data;
    size_t size;
};

class fuzzer_stream {
public:
    git_smart_subtransport_stream base;
    fuzzer_stream(fuzz_buffer data) : readp(data.data), endp(data.data + data.size) {
        base.read = fuzzer_stream::read;
        base.write = fuzzer_stream::write;
        base.free = fuzzer_stream::free;
    }

    int do_read(char *buffer, size_t buf_size, size_t *bytes_read) {
        size_t avail = endp - readp;
        *bytes_read = std::min(buf_size, avail);
        memcpy(buffer, readp, *bytes_read);
        readp += *bytes_read;
        return 0;
    }

    static int read(git_smart_subtransport_stream *stream,
                    char *buffer,
                    size_t buf_size,
                    size_t *bytes_read) {
        fuzzer_stream *fs = reinterpret_cast<fuzzer_stream*>(stream);
        return fs->do_read(buffer, buf_size, bytes_read);
    }

    static int write(git_smart_subtransport_stream *stream,
              const char *buffer,
              size_t len) {
        return 0;
    }

    static void free(git_smart_subtransport_stream *stream) {
        fuzzer_stream *fs = reinterpret_cast<fuzzer_stream*>(stream);
        delete fs;
    }
private:
    const uint8_t *readp;
    const uint8_t *endp;
};

class fuzzer_subtransport {
public:
    git_smart_subtransport base;
    fuzzer_subtransport(git_transport *owner, fuzz_buffer data) : owner(owner), data(data) {
        base.action = fuzzer_subtransport::action;
        base.close = fuzzer_subtransport::close;
        base.free = fuzzer_subtransport::free;
    }

    int do_action(git_smart_subtransport_stream **out,
                  git_smart_subtransport *transport,
                  const char *url,
                  git_smart_service_t action) {
        fuzzer_stream *stream = new fuzzer_stream(this->data);
        *out = &stream->base;
        return 0;
    }

    static int action(git_smart_subtransport_stream **out,
                      git_smart_subtransport *transport,
                      const char *url,
                      git_smart_service_t action) {
        fuzzer_subtransport *ft = reinterpret_cast<fuzzer_subtransport*>(transport);
        return ft->do_action(out, transport, url, action);
    }

    static int close(git_smart_subtransport *transport) {
        return 0;
    }

    static void free(git_smart_subtransport *transport) {
        fuzzer_subtransport *ft = reinterpret_cast<fuzzer_subtransport*>(transport);
        delete ft;
    }

private:
    git_transport *owner;
    fuzz_buffer data;
};

int fuzzer_subtransport_cb(git_smart_subtransport **out,
                           git_transport* owner,
                           void* param) {
    fuzz_buffer *buf = static_cast<fuzz_buffer*>(param);
    fuzzer_subtransport *sub = new fuzzer_subtransport(owner, *buf);

    *out = &sub->base;
    return 0;
}

int create_fuzzer_transport(git_transport **out, git_remote *owner, void *param) {
    git_smart_subtransport_definition fuzzer_subtransport {fuzzer_subtransport_cb, 1, param};
    return git_transport_smart(out, owner, &fuzzer_subtransport);
}

void fuzzer_git_abort(const char *op) {
    const git_error *err  = giterr_last();
    fprintf(stderr, "unexpected libgit error: %s: %s\n",
            op, err ? err->message : "<none>");
    abort();
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static git_repository *repo = nullptr;
  if (repo == nullptr) {
      git_libgit2_init();
      char tmp[] = "/tmp/git2.XXXXXX";
      if (mkdtemp(tmp) != tmp) {
          abort();
      }
      int err = git_repository_init(&repo, tmp, true);
      if (err != 0) {
          fuzzer_git_abort("git_repository_init");
      }
  }

  int err;
  git_remote *remote;
  err = git_remote_create_anonymous(&remote, repo, "fuzzer://remote-url");
  if (err != 0) {
      fuzzer_git_abort("git_remote_create");
  }


  fuzz_buffer buffer = {data, size};
  git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
  callbacks.transport = create_fuzzer_transport;
  callbacks.payload = &buffer;

  err = git_remote_connect(remote, GIT_DIRECTION_FETCH, &callbacks, nullptr, nullptr);
  if (err != 0) {
      goto out;
  }

  git_remote_download(remote, nullptr, nullptr);

 out:
  git_remote_free(remote);

  return 0;
}
