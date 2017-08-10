CC=gcc
CXX=g++
RM=-rm -f

source = $(wildcard *.c)
object = $(patsubst %.c, %.o, $(source))

all:pcap_mmap_test

%.o:%.cpp
	$(CXX) -c $< -o $@

pcap_mmap_test:$(object)
	$(CC) -Wall -o $@ $(object)

.PHONY:default clean
clean:
	$(RM) pcap_mmap_test $(object)

install:
	sudo cp pcap_mmap_test /usr/local/bin
uninstall:
	sudo rm /usr/local/bin/pcap_mmap_test
