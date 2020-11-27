- I initially disabled MSan because building glib from its source was
  [failing](https://github.com/google/oss-fuzz/runs/1456033255#step:7:5719) with
  MSan. In the new PR, I disabled glib (plus cairo and pango since they were
  only used by the glib fuzzers) and the glib fuzzers since Albert wants to have
  MSan. I am not sure why glib+MSan does not work in Poppler since the same
  combination seems to be working in Cairo and Gdk-Pixbuf (MSan still
  [fails](https://github.com/google/oss-fuzz/runs/1456033255#step:7:5719) but
  after succesfully building glib).

- Looks like building Poppler with MSan
  [fails](https://github.com/google/oss-fuzz/runs/1465507825?check_suite_focus=true#step:7:2896)
  because of an error in building Qt.

- I forgot removing `FuzzedDataProvider.h` from my repository so the three
  fuzzers that use `FuzzedDataProvider` (`doc_fuzzer.cc`,
  `page_search_fuzzer.cc` and `page_label_fuzzer.cc`) included this header file.
  Since presubmit checks failed because FuzzedDataProvider.h did not have the
  correct license header and I should have anyway removed it from this
  repository. I added three patch files that fix the include paths in these fuzz
  targets (change to `<fuzzer/FuzzedDataProvider.h>`).
