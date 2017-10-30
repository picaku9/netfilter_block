all : netfilter_block

netfilter_block: main.o
	g++ -g -o netfilter_block main.o -lnetfilter_queue

main.o:
	g++ -g -c -o main.o nfqnl_test

clean:
	rm -f netfileter_block
	rm -f *.o

