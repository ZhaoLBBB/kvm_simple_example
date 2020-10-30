all: main test.bin

main: main.o
	gcc main.c -o main

test.bin: test.o
	ld -m elf_i386 --oformat binary -N -e _start -Ttext 0x0 -o test.bin test.o

test.o: test.S
	as -32 test.S -o test.o
clean:
	rm -rf *.o main test.bin
