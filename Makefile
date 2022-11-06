CPPFLAGS = -Wall -Wextra -pedantic -Iinclude/ -g
TARGETS = Makefile Readme.md manual.pdf *.c *.h

.PHONY: all sender receiver common tester sender_events receiver_events clean pack

all: clean common sender receiver tester

sender: sender_events
	gcc sender/dns_sender.c -o sender/dns_sender.o -c
	gcc -o dns_sender  common/common.o sender/dns_sender.o sender/dns_sender_events.o

receiver: receiver_events
	gcc receiver/dns_receiver.c -o receiver/dns_receiver.o -c -g
	gcc -o dns_receiver common/common.o receiver/dns_receiver.o receiver/dns_receiver_events.o

common:
	gcc common/common.c -o common/common.o -c

tester:
	gcc tester/dns_tester.c -o tester/dns_tester.o -c -g
	gcc -o dns_tester tester/dns_tester.o

sender_events:
	gcc sender/dns_sender_events.c -o sender/dns_sender_events.o -c

receiver_events:
	gcc receiver/dns_receiver_events.c -o receiver/dns_receiver_events.o -c

pack: clean
	tar -cvzf xkrato61.tar common/* receiver/* sender/* tester/* README Makefile manual.pdf

clean:
	rm -f sender/*.o receiver/*.o common/*.o tester/*.o
	rm -f dns_sender dns_receiver dns_tester