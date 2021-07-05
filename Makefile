
all: libemaillight.o libemail.o email

CCOPTS=-I. -I/usr/local/ssl/include -D_GNU_SOURCE --std=gnu99 -g -Wall -funsigned-char -std=c99 -lpopt
OPTS=-L/usr/local/ssl/lib ${CCOPTS}

libemaillight.o: libemail.c
	cc -fPIC -O -DLIB -c -o $@ $< ${CCOPTS} -DLIGHT

libemail.o: libemail.c
	cc -fPIC -O -DLIB -c -o $@ $< ${CCOPTS}

email: libemail.c
	cc -O -o $@ $< ${OPTS} -lm -lcrypto -lcurl ${shell gpgme-config --libs --cflags}
