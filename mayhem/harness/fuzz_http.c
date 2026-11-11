FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/open.h>
#include "fuzz_net.h"

PROVIDE_REQUIRING_SYMBOL();

/* Initial send sequence number of the server's side of each connection */
#define HTTP_ISS 0x10000000

static const uint8_t *http_response;
static size_t http_response_len;

/* A client connection to the server, identified by the client's port */
struct http_conn {
	unsigned int port;
	uint32_t seq;
	int responded;
};

static struct http_conn http_conns[4];
static unsigned int http_num_conns;

/*
 * The web server accepts each connection, and answers the first request on it with the input
 * followed by FIN, so the input is the whole response (headers, body and its framing).
 */
static void http_server ( struct net_device *netdev,
			  const struct fuzznet_pkt *pkt ) {
	const struct tcp_header *tcp = pkt->tcp;
	struct http_conn *conn = NULL;
	unsigned int port;
	uint32_t ack;
	size_t offset;
	size_t frag;
	unsigned int i;

	if ( ! tcp )
		return;
	port = ntohs ( tcp->src );
	for ( i = 0 ; i < http_num_conns ; i++ ) {
		if ( http_conns[i].port == port )
			conn = &http_conns[i];
	}
	ack = ( ntohl ( tcp->seq ) + pkt->len );

	if ( tcp->flags & TCP_SYN ) {
		if ( ! conn ) {
			if ( http_num_conns == ( sizeof ( http_conns ) /
						 sizeof ( http_conns[0] ) ) )
				return;
			conn = &http_conns[http_num_conns++];
		}
		conn->port = port;
		conn->seq = HTTP_ISS;
		conn->responded = 0;
		fuzznet_rx_tcp ( netdev, pkt->dest, pkt->src,
				 ntohs ( tcp->dest ), port, conn->seq,
				 ( ack + 1 ), ( TCP_SYN | TCP_ACK ), NULL, 0 );
		conn->seq++;
		return;
	}
	if ( ( ! conn ) || conn->responded || ( ! pkt->len ) )
		return;
	conn->responded = 1;
	for ( offset = 0 ; offset < http_response_len ; offset += frag ) {
		frag = ( http_response_len - offset );
		if ( frag > FUZZNET_MSS )
			frag = FUZZNET_MSS;
		fuzznet_rx_tcp ( netdev, pkt->dest, pkt->src,
				 ntohs ( tcp->dest ), port, conn->seq, ack,
				 ( TCP_PSH | TCP_ACK ),
				 ( http_response + offset ), frag );
		conn->seq += frag;
	}
	fuzznet_rx_tcp ( netdev, pkt->dest, pkt->src, ntohs ( tcp->dest ),
			 port, conn->seq, ack, ( TCP_FIN | TCP_ACK ), NULL, 0 );
	conn->seq++;
}

/* Fetch a URL from a web server whose response is the input. */
static void fuzz_http ( const void *data, size_t len ) {
	struct net_device *netdev;
	struct interface app;

	srandom ( 1 );
	netdev = fuzznet_up();
	if ( ! netdev )
		return;
	fuzznet_set ( netdev, "net0/ip", "192.168.0.1" );
	fuzznet_set ( netdev, "net0/netmask", "255.255.255.0" );
	fuzznet_set ( netdev, "net0/gateway", "192.168.0.254" );
	http_response = data;
	http_response_len = len;
	http_num_conns = 0;
	fuzznet_server = http_server;
	intf_init ( &app, &fuzznet_sink_desc, NULL );
	if ( xfer_open_uri_string ( &app, "http://192.168.0.50/boot.ipxe" ) == 0 )
		fuzznet_steps();
	intf_shutdown ( &app, 0 );
	fuzznet_server = NULL;
	fuzznet_down ( netdev );
}

FUZZ_TARGET ( fuzz_http )
