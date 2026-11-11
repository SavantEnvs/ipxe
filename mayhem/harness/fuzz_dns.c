FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/resolv.h>
#include "fuzz_net.h"

PROVIDE_REQUIRING_SYMBOL();

static const uint8_t *dns_reply;
static size_t dns_reply_len;
static unsigned int dns_answered;

/*
 * The name server answers the first query with the input.  A resolver discards a response whose ID
 * is not the one of its outstanding query (RFC 1035 section 4.1.1), and iPXE picks the ID at random,
 * so the reply echoes the query's ID as a real server does; everything else is the input's.
 */
static void dns_server ( struct net_device *netdev,
			 const struct fuzznet_pkt *pkt ) {
	uint8_t *reply;

	if ( ! pkt->udp || ( pkt->udp->dest != htons ( 53 ) ) ||
	     ( dns_answered++ != 0 ) || ( pkt->len < 2 ) )
		return;
	reply = malloc ( dns_reply_len ? dns_reply_len : 1 );
	if ( ! reply )
		return;
	memcpy ( reply, dns_reply, dns_reply_len );
	if ( dns_reply_len >= 2 )
		memcpy ( reply, pkt->data, 2 );
	fuzznet_rx_udp ( netdev, fuzznet_client_mac, pkt->dest, pkt->src,
			 53, ntohs ( pkt->udp->src ), reply, dns_reply_len );
	free ( reply );
}

/* Resolve a name against a name server that replies with the input. */
static void fuzz_dns ( const void *data, size_t len ) {
	struct net_device *netdev;
	struct interface app;
	struct sockaddr_tcpip st;

	srandom ( 1 );
	netdev = fuzznet_up();
	if ( ! netdev )
		return;
	fuzznet_set ( netdev, "net0/ip", "192.168.0.1" );
	fuzznet_set ( netdev, "net0/netmask", "255.255.255.0" );
	fuzznet_set ( netdev, "net0/gateway", "192.168.0.254" );
	fuzznet_set ( netdev, "net0/dns", "192.168.0.53" );
	dns_reply = data;
	dns_reply_len = len;
	dns_answered = 0;
	fuzznet_server = dns_server;
	intf_init ( &app, &fuzznet_sink_desc, NULL );
	memset ( &st, 0, sizeof ( st ) );
	if ( resolv ( &app, "boot.example.com",
		      ( struct sockaddr * ) &st ) == 0 )
		fuzznet_steps();
	intf_shutdown ( &app, 0 );
	fuzznet_server = NULL;
	fuzznet_down ( netdev );
}

FUZZ_TARGET ( fuzz_dns )
