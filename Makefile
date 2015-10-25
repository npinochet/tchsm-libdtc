LIBSODIUM=/home/fmontoto/Resources/libsodium-1.0.3/install
ZMQ=/home/fmontoto/Resources/zeromq-4.1.3/install
TCLIB=/home/fmontoto/Resources/tclib/install
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

err.o: err.h err.c
	$(CC) $(CFLAGS) -c err.c

logger.o: logger/logger.c logger/logger.h
	$(CC) $(CFLAGS) -c logger/logger.c

database.o: database.c err.h database.h
	$(CC) $(CFLAGS) -c database.c

messages.o: messages.c messages.h logger/logger.h
	$(CC) $(CFLAGS) $(JSONC_I) -c messages.c

node.o: node.c logger/logger.h
	$(CC) $(CFLAGS) $(ZMQ_I) -c node.c

master.o: master.c err.h
	$(CC) $(CFLAGS) $(TCLIB_I) $(ZMQ_I) -c master.c

utilities.o: utilities.h utilities.c logger/logger.h
	$(CC) $(CFLAGS) $(LIBCONFIG_I) -c utilities.c

structs.o: structs.c structs.h
	$(CC) $(CFLAGS) -c structs.c

node: logger.o messages.o node.o err.o database.o utilities.o
	$(CXX) $(LDFLAGS) $(CFLAGS) $(TCLIB_L) $(ZMQ_L) $(LIBCONFIG_L) $(LIBSODIUM_L) $(JSONC_L) -L/usr/local/lib messages.o utilities.o node.o err.o database.o logger.o -o node -Wl,-Bstatic -lconfig -lzmq -lsodium -ljson-c -ltc -Wl,-Bdynamic -lpthread

master: master.o err.o logger.o messages.o utilities.o structs.o
	$(CXX) $(CXXFLAGS) $(ZMQ_I) $(TCLIB_L) $(JSONC_L) $(LIBCONFIG_I) $(LIBCONFIG_L) $(TCLIB_L) $(LIBSODIUM_L) $(LDFLAGS) $(ZMQ_L) utilities.o err.o master.o messages.o logger.o structs.o -o master  -Wl,-Bstatic -ltc -lconfig -lzmq -lsodium -ljson-c -ltc -Wl,-Bdynamic -lpthread

unit_test: unit_test.c database.o messages.o logger.o utilities.o
	$(CC) $(CFLAGS) $(TCLIB_L) $(JSONC_L) $(LIBCONFIG_L) database.o messages.o logger.o utilities.o unit_test.c $(LDFLAGS) -Wl,-Bstatic -ljson-c -ltc -lconfig -Wl,-Bdynamic -o unit_test

structs_test: structs_test.c structs.o
	$(CC) $(CFLAGS) structs_test.c structs.o $(LDFLAGS) -o structs_test

check: unit_test structs_test
	./unit_test && ./structs_test

check_structs: structs_test
	./structs_test

$(EXE): $(OBJS) $(OBJSLIBS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

tclib/libtc.a: force_look
	cd tclib; $(MAKE) $(MFLAGS)

lockless-queue/locklessqueue.o: force_look
	cd lockless-queue; $(MAKE) $(MFLAGS)

clean:
	-rm -f *.o node unit_test master structs_test

force_look:
	true
