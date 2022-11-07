CPPFLAGS = -Wall -Wextra -pedantic -Iinclude/
TARGETS = Makefile Readme.md manual.pdf *.c *.h

.PHONY: all sender receiver common tester sender_events receiver_events clean pack

all: clean common sender receiver

sender: sender_events
	gcc -o sender/dns_sender.o sender/dns_sender.c -c $(CPPFLAGS)
	gcc -o dns_sender  common/common.o sender/dns_sender.o sender/dns_sender_events.o $(CPPFLAGS)

receiver: receiver_events
	gcc -o receiver/dns_receiver.o receiver/dns_receiver.c -c $(CPPFLAGS)
	gcc -o dns_receiver common/common.o receiver/dns_receiver.o receiver/dns_receiver_events.o $(CPPFLAGS)

common:
	gcc -o common/common.o common/common.c -c $(CPPFLAGS)

tester: common
	gcc -o tester/dns_tester.o tester/dns_tester.c -c $(CPPFLAGS)
	gcc -o dns_tester tester/dns_tester.o common/common.o $(CPPFLAGS)

sender_events:
	gcc -o sender/dns_sender_events.o sender/dns_sender_events.c -c $(CPPFLAGS)

receiver_events:
	gcc -o receiver/dns_receiver_events.o receiver/dns_receiver_events.c -c $(CPPFLAGS)

pack: clean
	tar -cvzf xkrato61.tar common/* receiver/* sender/* tester/* README Makefile manual.pdf

clean:
	rm -f sender/*.o receiver/*.o common/*.o tester/*.o
	rm -f dns_sender dns_receiver dns_tester
	rm -f xkrato61.tar