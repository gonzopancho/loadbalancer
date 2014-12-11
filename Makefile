.PHONY: run all clean

CFLAGS = -I ../../include -O0 -g -Wall -Werror -m64 -ffreestanding -fno-stack-protector -std=gnu99

DIR = obj

OBJS = obj/main.o

LIBS = ../../lib/libpacketngin.a

all: $(OBJS)
	ld -melf_x86_64 -nostdlib -e main -o main $^ $(LIBS)
	make -C util

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj
	rm -f main
	rm -f configure
	make -C util clean

run: all
	../../bin/console script
