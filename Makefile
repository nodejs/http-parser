CPPFLAGS?=-Wall -Wextra -Werror -I. -fPIC
OPT_DEBUG=$(CPPFLAGS) -O0 -g -DHTTP_PARSER_STRICT=1
OPT_FAST=$(CPPFLAGS) -O3 -DHTTP_PARSER_STRICT=0

CC?=gcc
AR?=ar
GIT?=git

LIBEXT?=so
LIBPRE?=lib

GIT_VERSION:=$(shell $(GIT) log -1 --format=%H || echo Unknown)$(shell $(GIT) status --porcelain |grep "^[ MARCDU][ MDAU] " > /dev/null && echo "-Modified")

test: ltest_g test_g test_fast
	./ltest_g
	./test_g
	./test_fast

ltest: test.o $(LIBPRE)http_parser.$(LIBEXT)
	$(CC) $(OPT_FAST) -o $@ -Wl,-rpath=. -L. -lhttp_parser $<

ltest_g: test_g.o $(LIBPRE)http_parser_g.$(LIBEXT)
	$(CC) $(OPT_FAST) -o $@ -Wl,-rpath=. -L. -lhttp_parser_g $<

test_g: http_parser_g.a test_g.o
	$(CC) $(OPT_DEBUG) test_g.o http_parser_g.a -o $@

test_g.o: test.c http_parser.h Makefile
	$(CC) $(OPT_DEBUG) -c test.c -o $@

test.o: test.c http_parser.h Makefile
	$(CC) $(OPT_FAST) -c test.c -o $@

http_parser_g.o: http_parser.c http_parser.h Makefile
	$(CC) $(OPT_DEBUG) -c http_parser.c -o $@

test-valgrind: test_g
	valgrind ./test_g

http_parser.o: http_parser.c http_parser.h Makefile
	$(CC) $(OPT_FAST) -c http_parser.c

test_fast: http_parser.a test.c http_parser.h
	$(CC) $(OPT_FAST) test.c http_parser.a -o $@

test-run-timed: test_fast
	while(true) do time ./test_fast > /dev/null; done

http_parser.a: http_parser.o version.o
	$(AR) rcs $@ $^

http_parser_g.a: http_parser_g.o version_g.o
	$(AR) rcs $@ $^

$(LIBPRE)http_parser.$(LIBEXT): http_parser.o version.o
	$(CC) -shared -Wl,-rpath=. -o $@ $^

$(LIBPRE)http_parser_g.$(LIBEXT): http_parser_g.o version_g.o
	$(CC) -shared -Wl,-rpath=. -o $@ $^

version-$(GIT_VERSION).c : Makefile
	echo "const char * http_git_version() { return \"$(GIT_VERSION)\"; }" > $@

version.o: version-$(GIT_VERSION).c
	$(CC) $(OPT_FAST) -c $< -o $@

version_g.o: version-$(GIT_VERSION).c
	$(CC) $(OPT_DEBUG) -c $< -o $@

package: http_parser.o
	$(AR) rcs libhttp_parser.a http_parser.o

tags: http_parser.c http_parser.h test.c
	ctags $^

clean:
	rm -f *.o *.a *.so test test_fast test_g http_parser.tar tags version-*.c

.PHONY: clean package test-run test-run-timed test-valgrind
