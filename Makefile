#OPT=-O0 -gdwarf-2 -g3
OPT=-O3

test: http_parser.o test.c 
	gcc $(OPT) $^ -o $@ 

http_parser.o: http_parser.c http_parser.h Makefile
	gcc $(OPT) -c  $<

http_parser.c: http_parser.rl Makefile
	ragel -s -G2 $< -o $@

tags: http_parser.rl http_parser.h test.c
	ctags $^

clean:
	rm -f *.o http_parser.c test

.PHONY: clean
