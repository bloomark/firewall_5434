CC = gcc
CCOPTS = -c -g -Wall -ggdb -funsigned-char -pthread
LINKOPTS = -ggdb

all: main

main: main.o rule_parse.o pcap_handler.o virtual_interface.o physical_interface.o
	$(CC) $(LINKOPTS) -o $@ $^ -lpcap -lpthread -ggdb

%.o: %.c %.h
	gcc -g -Wall -c $< -o $@ -lpcap -lpthread -ggdb

clean:
	rm -rf *.o main firewalldump.pcap
