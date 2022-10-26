TARGET=Fuzzing

CUPS=FuzzCUPS
IPP=FuzzIPP
PPD=FuzzPPD

INCDIR=-I./../ -I./../cups/
MACRO=-D_CUPS_SOURCE -D_FORTIFY_SOURCE=2 -D_REENTRANT -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_THREAD_SAFE -D_REENTRANT
EXTFLAGS=-Wall -Werror
LIBDIR=-L./../cups/
LibFLAGS=$(LIBDIR) $(LIB_FUZZING_ENGINE) -lcups -lcupsimage -lssl -lcrypto -lz -lpthread

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(CUPS).c
	$(CC) $(CFLAGS) $(EXTFLAGS) $(MACRO) $(INCDIR) -c $(IPP).c

	$(CXX) $(CFLAGS) -o $(CUPS) $(CUPS).o $(LibFLAGS)
	$(CXX) $(CFLAGS) -o $(IPP) $(IPP).o $(LibFLAGS)

clean:
	rm $(CUPS) $(IPP) $(PPD) *.o

.PHONY: all clean
