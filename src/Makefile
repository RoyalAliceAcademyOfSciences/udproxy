udproxy: udproxy.o
	$(CC) $(LDFLAGS) *.o -o udproxy -lnfnetlink -lnetfilter_queue -luv -O3
%.o: %.c
	$(CC) $(CFLAGS) -c *.c utlist.h -O3
# remove object files and executable when user executes "make clean"
clean:
	rm *.gch *.o udproxy
