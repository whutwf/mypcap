CC=gcc
CXX=g++
RM=-rm -f
OUTDIR = ../output

source = $(wildcard *.c)
object = $(patsubst %.c, $(OUTDIR)/%.o, $(source))

all:sock_op_test

$(OUTDIR)/%.o:%.c
	$(CC) -c $< -o $@

sock_op_test:$(object)
	$(CC) -Wall -o $@ $(object)

.PHONY:default clean
clean:
	$(RM) sock_op_test $(object)

install:
	sudo cp sock_op_test /usr/local/bin
uninstall:
	sudo rm /usr/local/bin/sock_op_test
