

all: sender receiver

sender: dyn_string common
	gcc dns_sender.c -o dns_sender.o -c
	gcc -o dns_sender dyn_string.o common.o dns_sender.o

receiver: dyn_string common
	gcc dns_receiver.c -o dns_receiver.o -c
	gcc -o dns_receiver dyn_string.o common.o dns_receiver.o

dyn_string:
	gcc dyn_string.c -o dyn_string.o -c

common:
	gcc common.c -o common.o -c

clean:
	rm *.o
	rm -f dns_sender
	rm -f dns_receiver