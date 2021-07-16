
#COMPILE_OPTIONS = -O3 -fomit-frame-pointer -ffast-math -fno-math-errno -g -fno-strict-aliasing -Wno-unused-value -Wno-unused -march=core2 ${CXXFLAGS} -stdlib=libc++
COMPILE_OPTIONS =-fomit-frame-pointer -ffast-math -fno-math-errno -g -fno-strict-aliasing -Wno-unused-value -Wno-unused -march=core2 ${CXXFLAGS}
#-stdlib=libc++
LINKER_OPTIONS = -lpthread -g ${CXXFLAGS} -stdlib=libc++

OBJECTS = \
  crn_arealist.o \
  crn_assert.o \
  crn_checksum.o \
  crn_colorized_console.o \
  crn_command_line_params.o \
  crn_comp.o \
  crn_console.o \
  crn_core.o \
  crn_data_stream.o \
  crn_mipmapped_texture.o \
  crn_decomp.o \
  crn_dxt1.o \
  crn_dxt5a.o \
  crn_dxt.o \
  crn_dxt_endpoint_refiner.o \
  crn_dxt_fast.o \
  crn_dxt_hc_common.o \
  crn_dxt_hc.o \
  crn_dxt_image.o \
  crn_dynamic_string.o \
  crn_file_utils.o \
  crn_find_files.o \
  crn_hash.o \
  crn_hash_map.o \
  crn_huffman_codes.o \
  crn_image_utils.o \
  crnlib.o \
  crn_math.o \
  crn_mem.o \
  crn_pixel_format.o \
  crn_platform.o \
  crn_prefix_coding.o \
  crn_qdxt1.o \
  crn_qdxt5.o \
  crn_rand.o \
  crn_resample_filters.o \
  crn_resampler.o \
  crn_ryg_dxt.o \
  crn_sparse_bit_array.o \
  crn_stb_image.o \
  crn_strutils.o \
  crn_symbol_codec.o \
  crn_texture_file_types.o \
  crn_threaded_resampler.o \
  crn_threading_pthreads.o \
  crn_timer.o \
  crn_utils.o \
  crn_value.o \
  crn_vector.o \
  crn_zeng.o \
  crn_texture_comp.o \
  crn_texture_conversion.o \
  crn_dds_comp.o \
  crn_lzma_codec.o \
  crn_ktx_texture.o \
  crn_etc.o \
  crn_rg_etc1.o \
  crn_miniz.o \
  crn_jpge.o \
  crn_jpgd.o \
  lzma_7zBuf2.o \
  lzma_7zBuf.o \
  lzma_7zCrc.o \
  lzma_7zFile.o \
  lzma_7zStream.o \
  lzma_Alloc.o \
  lzma_Bcj2.o \
  lzma_Bra86.o \
  lzma_Bra.o \
  lzma_BraIA64.o \
  lzma_LzFind.o \
  lzma_LzmaDec.o \
  lzma_LzmaEnc.o \
  lzma_LzmaLib.o

all: crunch_fuzz

%.o: %.cpp
	${CXX} $< -o $@ -c $(COMPILE_OPTIONS)

crunch.o: ../crunch/crunch.cpp
	${CXX} $< -o $@ -c -I../inc -I../crnlib $(COMPILE_OPTIONS)

corpus_gen.o: ../crunch/corpus_gen.cpp
	${CXX} $< -o $@ -c -I../inc -I../crnlib $(COMPILE_OPTIONS)

corpus_test.o: ../crunch/corpus_test.cpp
	${CXX} $< -o $@ -c -I../inc -I../crnlib $(COMPILE_OPTIONS)

crunch_fuzz: $(OBJECTS)
	${CXX} ${CXXFLAGS} ${LIB_FUZZING_ENGINE} -I../inc -I../crnlib crunch_fuzz.cpp -o $@ $(OBJECTS)
