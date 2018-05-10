HEADERS = aes.h

default: compile

compile.o: aes.c $(HEADERS)
	gcc -Wall -pedantic -ansi -g -std=c11 -O0 -c aes.c -o aes.o

compile: compile.o
	gcc aes.o -o aes
	@echo "Compilación correcta"

clean:
	-rm -f aes.o aes
