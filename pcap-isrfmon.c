/*
 * Copyright (c) 2016, CodeWard.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

int
main (int argc, char *argv[])
{
	char *iface;
	pcap_t *pcap_res;
	int exitno, isrfmon;
	char errbuf[PCAP_ERRBUF_SIZE];

	exitno = EXIT_SUCCESS;
	pcap_res = NULL;

	if ( argc < 2 ){
		fprintf (stdout, "Usage: %s <INTERFACE>\n\nCheck if an INTERFACE supports a monitor mode (rfmon).\n", argv[0]);
		exitno = 2;
		goto cleanup;
	}

	iface = argv[1];

	pcap_res = pcap_create (iface, errbuf);

	if ( pcap_res == NULL ){
		fprintf (stderr, "%s: cannot open interface for a packet capture: %s\n", argv[0], errbuf);
		exitno = 2;
		goto cleanup;
	}

	isrfmon = pcap_can_set_rfmon (pcap_res);

	if ( isrfmon == 0 ){
		fprintf (stderr, "not supported\n");
		exitno = 1;
		goto cleanup;
	} else if ( isrfmon == 1 ){
		// Attempt to activate a packet capture	
		// ...
	} else {
		fprintf (stderr, "%s: cannot obtain information about rfmon support: %s\n", argv[0], pcap_geterr (pcap_res));
		exitno = 2;
		goto cleanup;
	}

	isrfmon = pcap_set_rfmon (pcap_res, 1);

	if ( isrfmon != 0 ){
		fprintf (stderr, "%s: cannot set an interface to monitor mode: %s\n", argv[0], pcap_geterr (pcap_res));
		exitno = 2;
		goto cleanup;
	}

	isrfmon = pcap_activate (pcap_res);

	if ( isrfmon == PCAP_ERROR_RFMON_NOTSUP ){
		fprintf (stderr, "not supported\n");
		exitno = 1;
	} else if ( isrfmon == 0 ){
		fprintf (stderr, "supported\n");
		exitno = 0;
	} else {
		fprintf (stderr, "%s: cannot activate a packet capture: %s\n", argv[0], pcap_geterr (pcap_res));
		exitno = 2;
	}

cleanup:
	if ( pcap_res != NULL )
		pcap_close (pcap_res);

	return exitno;
}

