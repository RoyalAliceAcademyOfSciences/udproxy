udproxy: udproxy.o
	$(CC) $(LDFLAGS) udproxy.o -o udproxy -lnfnetlink -lnetfilter_queue -luv -O3
udproxy.o: udproxy.c
	$(CC) $(CFLAGS) -c udproxy.c utlist.h -O3
# remove object files and executable when user executes "make clean"
clean:
	rm *.gch *.o udproxy
