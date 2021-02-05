
CFLAGS += -I../src/tss2-esys -I../src/tss2-sys \
		-I../include/tss2 -I../ -I../src \
		-I/usr/include/openssl \
		-I/usr/include/x86_64-linux-gnu/openssl/ \
		-Wl,--no-as-needed -ldl
#Debug
#CFLAGS += -g -O0 -DDEBUG

all:
	$(CC) $(CFLAGS) -o random random.c \
	/usr/local/lib/libtss2-esys.a \
	/usr/local/lib/libtss2-sys.a \
	/usr/local/lib/libtss2-mu.a \
	/usr/local/lib/libtss2-tctildr.a \
	/usr/local/lib/libtss2-tcti-device.a \
	/usr/local/lib/libtss2-tcti-cmd.a \
	/usr/local/lib/libtss2-rc.a \
	/usr/lib/x86_64-linux-gnu/libcrypto.a \
	/usr/lib/x86_64-linux-gnu/libssl.a \
	/usr/lib/x86_64-linux-gnu/libpthread.a

clean:
	rm random
