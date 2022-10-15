CPPFLAGS = -Wall -Wextra -pedantic -Iinclude/ -g
TARGETS = Makefile Readme.md manual.pdf *.c *.h

all: clean sender receiver

sender: dyn_string common sender_events
	gcc dns_sender.c -o dns_sender.o -c
	gcc -o dns_sender dyn_string.o common.o dns_sender.o dns_sender_events.o

receiver: dyn_string common receiver_events
	gcc dns_receiver.c -o dns_receiver.o -c -g
	gcc -o dns_receiver dyn_string.o common.o dns_receiver.o dns_receiver_events.o

dyn_string:
	gcc dyn_string.c -o dyn_string.o -c

common:
	gcc common.c -o common.o -c

sender_events:
	gcc dns_sender_events.c -o dns_sender_events.o -c

receiver_events:
	gcc dns_receiver_events.c -o dns_receiver_events.o -c

pack:
	tar -cvzf # TODO



clean:
	rm -f *.o
	rm -f dns_sender
	rm -f dns_receiver