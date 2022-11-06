TARGET=Fuzzing

json=fuzz-json
xml=fuzz-xml
sdp=fuzz-sdp
stun=fuzz-stun
sip=fuzz-sip

SETINC=-I./..
SETLIB=-L./..
INCDIR= \
	$(SETINC)/pjlib/include \
	$(SETINC)/pjlib-util/include \
	$(SETINC)/pjnath/include \
	$(SETINC)/pjmedia/include \
	$(SETINC)/pjsip/include \
	$(SETINC)/third_party/include
LIBDIR= \
	$(SETLIB)/pjlib/lib \
	$(SETLIB)/pjlib-util/lib \
	$(SETLIB)/pjnath/lib \
	$(SETLIB)/pjmedia/lib \
	$(SETLIB)/pjsip/lib \
	$(SETLIB)/third_party/lib
pjlib=-lpjlib-util-x86_64-unknown-linux-gnu -lpj-x86_64-unknown-linux-gnu
pjmedia=-lpjmedia-codec-x86_64-unknown-linux-gnu -lpjmedia-videodev-x86_64-unknown-linux-gnu -lpjmedia-audiodev-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjnath-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu -lpj-x86_64-unknown-linux-gnu
pjnath=-lpjnath-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu -lpj-x86_64-unknown-linux-gnu
pjsip=-lpjsip-x86_64-unknown-linux-gnu -lpjsip-ua-x86_64-unknown-linux-gnu -lpjsip-simple-x86_64-unknown-linux-gnu  -lpjmedia-codec-x86_64-unknown-linux-gnu -lpjmedia-videodev-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjmedia-audiodev-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu -lpjnath-x86_64-unknown-linux-gnu -lpj-x86_64-unknown-linux-gnu

MACRO=-DPJ_AUTOCONF=1 -DPJ_IS_BIG_ENDIAN=0 -DPJ_IS_LITTLE_ENDIAN=1 -DPJMEDIA_HAS_SRTP=0
EXTFLAGS=-Wall -Werror
LibFLAGS=$(LIBDIR) $(LIB_FUZZING_ENGINE)

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(json).c
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(xml).c
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(sdp).c
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(stun).c
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(sip).c

	$(CXX) $(CFLAGS) -o $(json) $(json).o $(LibFLAGS) $(pjlib)
	$(CXX) $(CFLAGS) -o $(xml) $(xml).o $(LibFLAGS) $(pjlib)
	$(CXX) $(CFLAGS) -o $(sdp) $(sdp).o $(LibFLAGS) $(pjmedia)
	$(CXX) $(CFLAGS) -o $(stun) $(stun).o $(LibFLAGS) $(pjnath)
	$(CXX) $(CFLAGS) -o $(sip) $(sip).o $(LibFLAGS) $(pjsip)

clean:
	rm $(json) $(xml) $(sdp) $(stun) $(sip) *.o

.PHONY: all clean
