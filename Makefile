all : netfilter_block

netfilter_block: main.o
	gcc -g -o netfilter_block main.o -lnetfilter_queue

main.o:
	gcc -g -c -o main.o netfilter_block.c -lnetfilter_queue

clean:
	rm -f netfilter_block
	rm -f *.o
