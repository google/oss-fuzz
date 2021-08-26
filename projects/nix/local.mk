fuzz/parse_store_path: fuzz/target_parse_store_path.cc src/libstore/libnixstore.so src/libutil/libnixutil.so
	$(CXX) -v $(CPPFLAGS) $(GLOBAL_CXXFLAGS_PCH) $(GLOBAL_CXXFLAGS) $(nix_CXXFLAGS) $(fuzzer_CXXFLAGS) $(fuzzer_LDFLAGS) -o $@ $< $(libstore_LDFLAGS_USE)
