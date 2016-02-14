CFLAGS = -O2 -pedantic -ggdb -Wall

all: pcap-llt pcap-isrfmon

pcap-llt: pcap-llt.o
	$(CC) $(CFLAGS) $< -o $@ -lpcap

pcap-llt.o: pcap-llt.c
	$(CC) $(CFLAGS) -c $<

pcap-isrfmon: pcap-isrfmon.o
	$(CC) $(CFLAGS) $< -o $@ -lpcap

pcap-isrfmon.o: pcap-isrfmon.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o pcap-llt pcap-isrfmon

