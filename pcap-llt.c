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
	int *iface_linktype;
	pcap_t *pcap_res;
	int exitno, i, linktype_cnt;
	char errbuf[PCAP_ERRBUF_SIZE];

	exitno = EXIT_SUCCESS;
	pcap_res = NULL;

	if ( argc < 2 ){
		fprintf (stdout, "Usage: %s <INTERFACE>\n\nList supported link-types by an INTERFACE.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	iface = argv[1];

	pcap_res = pcap_create (iface, errbuf);

	if ( pcap_res == NULL ){
		fprintf (stderr, "%s: cannot open interface for a packet capture: %s\n", argv[0], errbuf);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( pcap_activate (pcap_res) != 0 ){
		fprintf (stderr, "%s: cannot activate a packet capture: %s\n", argv[0], pcap_geterr (pcap_res));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	linktype_cnt = pcap_list_datalinks (pcap_res, &iface_linktype);

	if ( linktype_cnt == -1 ){
		fprintf (stderr, "%s: cannot obtain list of supported link-types: %s\n", argv[0], pcap_geterr (pcap_res));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	for ( i = 0; i < linktype_cnt; i++ )
		fprintf (stderr, "%s\n", pcap_datalink_val_to_name (iface_linktype[i]));

	pcap_free_datalinks (iface_linktype);

cleanup:
	if ( pcap_res != NULL )
		pcap_close (pcap_res);

	return exitno;
}

