PREFIX=/usr
CFLAGS=-fPIC
all: libsimplesocket.a libsimplesocket.so simplesocket.pc

libsimplesocket.a: socket.o
	$(AR) rs $@ $^

libsimplesocket.so: socket.o
	$(CC) -shared $^ -o $@

simplesocket.pc:
	echo 'Name: libSimpleSocket' > $@
	echo 'Description: Abstract socket networking that seamlessly allows both unencrypted and encrypted connections' >> $@
	echo 'Version: 0.1' >> $@
	echo 'Requires: gnutls' >> $@
	echo 'Cflags: -I$(PREFIX)/include' >> $@
	echo 'Libs: -L$(PREFIX)/lib -lsimplesocket' >> $@

install: all
	install -m 644 socket.h -D $(PREFIX)/include/simplesocket/socket.h
	install -m 644 libsimplesocket.so -D $(PREFIX)/lib/libsimplesocket.so
	install -m 644 libsimplesocket.a -D $(PREFIX)/lib/libsimplesocket.a
	install -m 644 simplesocket.pc -D $(PREFIX)/lib/pkgconfig/simplesocket.pc

uninstall:
	rm -rf $(PREFIX)/include/simplesocket
	rm -f $(PREFIX)/lib/libsimplesocket.so
	rm -f $(PREFIX)/lib/libsimplesocket.a
	rm -f $(PREFIX)/lib/pkgconfig/simplesocket.pc

clean:
	rm -f libsimplesocket.a libsimplesocket.so socket.o simplesocket.pc
