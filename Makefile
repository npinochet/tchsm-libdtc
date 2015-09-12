LIBSODIUM=/home/fmontoto/Resources/libsodium-1.0.3/install
ZMQ=/home/fmontoto/Resources/zeromq-4.1.3/install
TCLIB=/home/fmontoto/Resources/tclib/pre
LIBCONFIG=/home/fmontoto/Resources/libconfig-1.5/install
JSONC=/home/fmontoto/Resources/json-c/install

LIBSODIUM_I=-I${LIBSODIUM}/include
LIBSODIUM_L=-L${LIBSODIUM}/lib
ZMQ_I=-I${ZMQ}/include
ZMQ_L=-L${ZMQ}/lib
LIBCONFIG_I=-I${LIBCONFIG}/include
LIBCONFIG_L=-L${LIBCONFIG}/lib
TCLIB_I=-I${TCLIB}/include
TCLIB_L =-L${TCLIB}/lib
JSONC_I=-I${JSONC}/include/json-c
JSONC_L=-L${JSONC}/lib

CC=clang
CXX=clang++
CFLAGS=-std=c11 -Werror -Wall -g
EXTRACFLAGS=
CXXFLAGS=-std=c++11 -Wall -Werror -g
LDFLAGS=-lpthread -luuid -lmhash -lgmp -lcheck -lm -lrt -lsqlite3
CFLAGS += ${TCLIB_I}
CFLAGS += ${LIBCONFIG_I}
ifdef UNIT_TEST
	CFLAGS += -D UNIT_TEST
endif
EXTRALDFLAGS=

EXE=model
OBJS=common.o master.o model.o node.o node_communication.c serialization.o threading.o logger.o
OBJSLIBS = $(TCLIB)/libtc.a lockless-queue/locklessqueue.o
LIBS= -L$(TCLIB)/tclib -ltc
DEPS=%.h

all: $(EXE)

logger.o: logger/logger.c logger/logger.h
	$(CC) $(CFLAGS) -c logger/logger.c

database.o: database.c err.h database.h
	$(CC) $(CFLAGS) -c database.c

messages.o: messages.c messages.h logger.o
	$(CC) $(CFLAGS) $(JSONC_I) -c messages.c

node.o: node.c logger/logger.c logger/logger.h
	$(CC) $(CFLAGS) $(ZMQ_I) -c node.c

master.o: master.c err.h
	$(CC) $(CFLAGS) $(ZMQ_I) -c master.c

node: logger.o messages.o node.o
	$(CXX) $(LDFLAGS) $(CFLAGS) $(ZMQ_L) $(JSONC_L) $(LIBSODIUM_L) -L/usr/local/lib messages.o node.o logger.o -o node -Wl,-Bstatic -lzmq -lsodium -ljson-c -Wl,-Bdynamic -lpthread

master: master.o logger.o messages.o
	$(CXX) $(CXXFLAGS) $(ZMQ_I) $(LIBCONFIG_I) $(LIBCONFIG_L) $(TCLIB_L) $(LIBSODIUM_L) $(LDFLAGS) $(ZMQ_L) master.o messages.o logger.o -o master  -Wl,-Bstatic -ltc -lconfig -luuid -lzmq -lsodium  -Wl,-Bdynamic -lpthread

unit_test: unit_test.c database.o messages.o logger.o
	$(CC) $(CFLAGS) $(JSONC_L) database.o messages.o logger.o unit_test.c $(LDFLAGS) -Wl,-Bstatic -ljson-c -Wl,-Bdynamic -o unit_test

check: unit_test
	./unit_test

$(EXE): $(OBJS) $(OBJSLIBS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

tclib/libtc.a: force_look
	cd tclib; $(MAKE) $(MFLAGS)

lockless-queue/locklessqueue.o: force_look
	cd lockless-queue; $(MAKE) $(MFLAGS)

clean:
	-rm -f *.o node unit_test master

force_look:
	true