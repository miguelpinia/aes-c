HEADERS = aes.h

default: compile

compile.o: aes.c $(HEADERS)
	gcc -Wall -pedantic -ansi -g -std=c11 -O0 -c aes.c -o aes.o

compile: compile.o
	gcc aes.o -o aes
	@echo "Compilación correcta"

clean:
	-rm -f aes.o aes

# default: compile

# compile.o: DemoRc2.c $(HEADERS)
# 	gcc -Wall -pedantic -ansi -c DemoRc2.c -o DemoRc2.o
# compile: compile.o
# 	gcc DemoRc2.o -o DemoRc2
# 	@echo "Compilación correcta"

# clean:
# 	-rm -f DemoRc2.o DemoRc2
