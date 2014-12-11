CFLAGS := -I ../../../../lib/core/include -Wall -Werror -std=gnu99

configure: src/configure.c
	gcc $(CFLAGS) -Wno-unused-variable -o $@ $^ -lcurl ../../../../lib/libcore_linux.a
	cp configure ..

config_NAT:
	./configure NAT.psh

config_DNAT:
	./configure DNAT.psh

config_DR:
	./configure DR.psh

clean:
	rm -rf configure
