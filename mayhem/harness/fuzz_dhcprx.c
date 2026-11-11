FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/dhcp.h>
#include <ipxe/dhcppkt.h>
#include "fuzz_net.h"

PROVIDE_REQUIRING_SYMBOL();

static const uint8_t *dhcp_reply;
static size_t dhcp_reply_len;
static unsigned int dhcp_replies;

/*
 * The DHCP server answers the client's DISCOVER with the input, and its REQUEST with the same
 * packet as an ACK.  A client discards replies that do not carry its transaction ID and hardware
 * address (RFC 2131 section 4.3.1); the ID is random, so the reply echoes both as a real server
 * does.  Everything else, including the options, is the input's.
 */
static void dhcp_server ( struct net_device *netdev,
			  const struct fuzznet_pkt *pkt ) {
	static const uint8_t ack = DHCPACK;
	struct dhcp_packet dhcppkt;
	struct dhcphdr *dhcphdr;
	struct in_addr server;
	struct in_addr broadcast;
	uint8_t *reply;

	if ( ! pkt->udp || ( pkt->udp->dest != htons ( BOOTPS_PORT ) ) ||
	     ( dhcp_replies >= 2 ) )
		return;
	reply = malloc ( dhcp_reply_len ? dhcp_reply_len : 1 );
	if ( ! reply )
		return;
	memcpy ( reply, dhcp_reply, dhcp_reply_len );
	if ( dhcp_reply_len >= sizeof ( *dhcphdr ) ) {
		dhcphdr = ( ( struct dhcphdr * ) reply );
		dhcphdr->xid = dhcp_last_xid;
		memcpy ( dhcphdr->chaddr, fuzznet_client_mac, ETH_ALEN );
		if ( dhcp_replies == 1 ) {
			dhcppkt_init ( &dhcppkt, dhcphdr, dhcp_reply_len );
			dhcppkt_store ( &dhcppkt, DHCP_MESSAGE_TYPE, &ack,
					sizeof ( ack ) );
		}
	}
	dhcp_replies++;
	server.s_addr = IPV4 ( 192, 168, 0, 254 );
	broadcast.s_addr = IPV4 ( 255, 255, 255, 255 );
	fuzznet_rx_udp ( netdev, fuzznet_broadcast_mac, server, broadcast,
			 BOOTPS_PORT, BOOTPC_PORT, reply, dhcp_reply_len );
	free ( reply );
}

/* Run the DHCP client against a server that replies with the input. */
static void fuzz_dhcprx ( const void *data, size_t len ) {
	struct net_device *netdev;
	struct interface job;

	srandom ( 1 );
	netdev = fuzznet_up();
	if ( ! netdev )
		return;
	dhcp_reply = data;
	dhcp_reply_len = len;
	dhcp_replies = 0;
	fuzznet_server = dhcp_server;
	intf_init ( &job, &fuzznet_sink_desc, NULL );
	if ( start_dhcp ( &job, netdev ) == 0 )
		fuzznet_steps();
	intf_shutdown ( &job, 0 );
	fuzznet_server = NULL;
	fuzznet_down ( netdev );
}

FUZZ_TARGET ( fuzz_dhcprx )
