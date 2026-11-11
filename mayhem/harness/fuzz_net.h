/*
 * Shared by the network-protocol fuzz harnesses (fuzz_dns, fuzz_dhcprx, fuzz_http): a fake Ethernet
 * segment with one scripted peer.  iPXE's own stack (ARP, IPv4, UDP, TCP, and the protocol under
 * test) runs for real on a stub network device; the peer answers ARP, and hands each target's
 * server callback every IPv4 packet the client transmits, so the callback can reply with fuzz bytes.
 */
#ifndef FUZZ_NET_H
#define FUZZ_NET_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdio.h>
#include <byteswap.h>
#include <ipxe/device.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/process.h>
#include <ipxe/settings.h>
#include <ipxe/in.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/ip.h>
#include <ipxe/udp.h>
#include <ipxe/tcp.h>
#include <ipxe/tcpip.h>
#include "fuzz_input.h"

/* Process steps to run after each stimulus; enough for the stack to settle */
#define FUZZNET_STEPS 128

/* A UDP datagram is at most 65535 - 20 (IPv4 header) - 8 (UDP header) bytes (RFC 768, RFC 791) */
#define FUZZNET_MAX_UDP ( 65535 - sizeof ( struct iphdr ) - sizeof ( struct udp_header ) )

/* Largest TCP segment payload we send (Ethernet MTU less IPv4 and TCP headers) */
#define FUZZNET_MSS 1400

static const uint8_t fuzznet_client_mac[ETH_ALEN] =
	{ 0x52, 0x54, 0x00, 0x59, 0xba, 0xc9 };
static const uint8_t fuzznet_peer_mac[ETH_ALEN] =
	{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static const uint8_t fuzznet_broadcast_mac[ETH_ALEN] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* An IPv4 packet transmitted by the client */
struct fuzznet_pkt {
	struct in_addr src;
	struct in_addr dest;
	uint8_t protocol;
	const struct udp_header *udp;
	const struct tcp_header *tcp;
	const void *data;
	size_t len;
};

/* The target's scripted peer: called for every UDP/TCP packet the client sends */
static void ( * fuzznet_server ) ( struct net_device *netdev,
				   const struct fuzznet_pkt *pkt );

/* A byte sink for interfaces whose far end we do not model */
static inline int fuzznet_sink_deliver ( struct interface *intf __unused,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta __unused ) {
	free_iob ( iobuf );
	return 0;
}

static struct interface_operation fuzznet_sink_op[] = {
	INTF_OP ( xfer_deliver, struct interface *, fuzznet_sink_deliver ),
};

static struct interface_descriptor fuzznet_sink_desc =
	INTF_DESC_PURE ( fuzznet_sink_op );

static inline void fuzznet_steps ( void ) {
	unsigned int i;

	for ( i = 0 ; i < FUZZNET_STEPS ; i++ )
		step();
}

/* Deliver a complete Ethernet frame to the client */
static inline void fuzznet_rx_frame ( struct net_device *netdev,
			       const uint8_t *dest_mac, uint16_t ethertype,
			       const void *payload, size_t len ) {
	struct io_buffer *iobuf;
	uint8_t *frame;

	iobuf = alloc_iob ( ETH_HLEN + len );
	if ( ! iobuf )
		return;
	frame = iob_put ( iobuf, ETH_HLEN + len );
	memcpy ( frame, dest_mac, ETH_ALEN );
	memcpy ( ( frame + ETH_ALEN ), fuzznet_peer_mac, ETH_ALEN );
	frame[12] = ( ethertype >> 8 );
	frame[13] = ( ethertype & 0xff );
	memcpy ( ( frame + ETH_HLEN ), payload, len );
	netdev_rx ( netdev, iobuf );
}

/* Deliver an IPv4 packet carrying a transport-layer segment to the client */
static inline void fuzznet_rx_ip ( struct net_device *netdev, const uint8_t *dest_mac,
			    struct in_addr src, struct in_addr dest,
			    uint8_t protocol, const void *segment,
			    size_t len ) {
	uint8_t *pkt = malloc ( sizeof ( struct iphdr ) + len );
	struct iphdr *ip = ( ( struct iphdr * ) pkt );

	if ( ! pkt )
		return;
	memset ( ip, 0, sizeof ( *ip ) );
	ip->verhdrlen = ( IP_VER | ( sizeof ( *ip ) / 4 ) );
	ip->len = htons ( sizeof ( *ip ) + len );
	ip->ttl = IP_TTL;
	ip->protocol = protocol;
	ip->src = src;
	ip->dest = dest;
	ip->chksum = tcpip_chksum ( ip, sizeof ( *ip ) );
	memcpy ( ( pkt + sizeof ( *ip ) ), segment, len );
	fuzznet_rx_frame ( netdev, dest_mac, ETH_P_IP, pkt,
			   ( sizeof ( *ip ) + len ) );
	free ( pkt );
}

/* Send a UDP datagram to the client (checksum 0 means "none", RFC 768) */
static inline void fuzznet_rx_udp ( struct net_device *netdev, const uint8_t *dest_mac,
			     struct in_addr src, struct in_addr dest,
			     unsigned int sport, unsigned int dport,
			     const void *data, size_t len ) {
	uint8_t *dgram;
	struct udp_header *udp;

	if ( len > FUZZNET_MAX_UDP )
		len = FUZZNET_MAX_UDP;
	dgram = malloc ( sizeof ( *udp ) + len );
	if ( ! dgram )
		return;
	udp = ( ( struct udp_header * ) dgram );
	udp->src = htons ( sport );
	udp->dest = htons ( dport );
	udp->len = htons ( sizeof ( *udp ) + len );
	udp->chksum = 0;
	memcpy ( ( dgram + sizeof ( *udp ) ), data, len );
	fuzznet_rx_ip ( netdev, dest_mac, src, dest, IP_UDP, dgram,
			( sizeof ( *udp ) + len ) );
	free ( dgram );
}

/* Send a TCP segment to the client */
static inline void fuzznet_rx_tcp ( struct net_device *netdev, struct in_addr src,
			     struct in_addr dest, unsigned int sport,
			     unsigned int dport, uint32_t seq, uint32_t ack,
			     uint8_t flags, const void *data, size_t len ) {
	struct ipv4_pseudo_header *pshdr;
	struct tcp_header *tcp;
	uint8_t *buf;
	size_t seglen = ( sizeof ( *tcp ) + len );

	buf = malloc ( sizeof ( *pshdr ) + seglen );
	if ( ! buf )
		return;
	pshdr = ( ( struct ipv4_pseudo_header * ) buf );
	tcp = ( ( struct tcp_header * ) ( buf + sizeof ( *pshdr ) ) );
	memset ( pshdr, 0, sizeof ( *pshdr ) );
	pshdr->src = src;
	pshdr->dest = dest;
	pshdr->protocol = IP_TCP;
	pshdr->len = htons ( seglen );
	memset ( tcp, 0, sizeof ( *tcp ) );
	tcp->src = htons ( sport );
	tcp->dest = htons ( dport );
	tcp->seq = htonl ( seq );
	tcp->ack = htonl ( ack );
	tcp->hlen = ( ( sizeof ( *tcp ) / 4 ) << 4 );
	tcp->flags = flags;
	tcp->win = htons ( 0xffff );
	memcpy ( ( tcp + 1 ), data, len );
	tcp->csum = tcpip_chksum ( buf, ( sizeof ( *pshdr ) + seglen ) );
	fuzznet_rx_ip ( netdev, fuzznet_peer_mac, src, dest, IP_TCP, tcp,
			seglen );
	free ( buf );
}

/* Observe a frame transmitted by the client: answer ARP, pass IPv4 to the target's server */
static inline void fuzznet_observe ( struct net_device *netdev, const uint8_t *frame,
			      size_t len ) {
	const struct iphdr *ip;
	struct fuzznet_pkt pkt;
	size_t hlen;
	size_t total;
	size_t tcplen;
	uint8_t arp[28];
	const uint8_t *req;

	if ( len < ETH_HLEN )
		return;
	if ( ( frame[12] == ( ETH_P_ARP >> 8 ) ) &&
	     ( frame[13] == ( ETH_P_ARP & 0xff ) ) ) {
		/* Answer every "who has" with the peer's address */
		req = ( frame + ETH_HLEN );
		if ( ( len < ( ETH_HLEN + sizeof ( arp ) ) ) || ( req[7] != 1 ) )
			return;
		memcpy ( arp, req, 8 );
		arp[7] = 2;
		memcpy ( ( arp + 8 ), fuzznet_peer_mac, ETH_ALEN );
		memcpy ( ( arp + 14 ), ( req + 24 ), 4 );
		memcpy ( ( arp + 18 ), ( req + 8 ), 10 );
		fuzznet_rx_frame ( netdev, fuzznet_client_mac, ETH_P_ARP,
				   arp, sizeof ( arp ) );
		return;
	}
	if ( ( frame[12] != ( ETH_P_IP >> 8 ) ) ||
	     ( frame[13] != ( ETH_P_IP & 0xff ) ) ||
	     ( len < ( ETH_HLEN + sizeof ( *ip ) ) ) )
		return;
	ip = ( ( const void * ) ( frame + ETH_HLEN ) );
	hlen = ( ( ip->verhdrlen & IP_MASK_HLEN ) * 4 );
	total = ntohs ( ip->len );
	if ( ( hlen < sizeof ( *ip ) ) || ( total < hlen ) ||
	     ( ( ETH_HLEN + total ) > len ) )
		return;
	memset ( &pkt, 0, sizeof ( pkt ) );
	pkt.src = ip->src;
	pkt.dest = ip->dest;
	pkt.protocol = ip->protocol;
	if ( ( ip->protocol == IP_UDP ) &&
	     ( ( total - hlen ) >= sizeof ( struct udp_header ) ) ) {
		pkt.udp = ( ( const void * ) ip + hlen );
		pkt.data = ( pkt.udp + 1 );
		pkt.len = ( total - hlen - sizeof ( struct udp_header ) );
	} else if ( ( ip->protocol == IP_TCP ) &&
		    ( ( total - hlen ) >= sizeof ( struct tcp_header ) ) ) {
		pkt.tcp = ( ( const void * ) ip + hlen );
		tcplen = ( ( pkt.tcp->hlen >> 4 ) * 4 );
		if ( ( tcplen < sizeof ( *pkt.tcp ) ) ||
		     ( tcplen > ( total - hlen ) ) )
			return;
		pkt.data = ( ( const void * ) pkt.tcp + tcplen );
		pkt.len = ( total - hlen - tcplen );
	} else {
		return;
	}
	if ( fuzznet_server )
		fuzznet_server ( netdev, &pkt );
}

static inline int fuzznet_open ( struct net_device *netdev __unused ) {
	return 0;
}

static inline void fuzznet_close ( struct net_device *netdev __unused ) {
}

static inline int fuzznet_transmit ( struct net_device *netdev,
			      struct io_buffer *iobuf ) {
	fuzznet_observe ( netdev, iobuf->data, iob_len ( iobuf ) );
	netdev_tx_complete ( netdev, iobuf );
	return 0;
}

static inline void fuzznet_poll ( struct net_device *netdev __unused ) {
}

static struct net_device_operations fuzznet_operations = {
	.open		= fuzznet_open,
	.close		= fuzznet_close,
	.transmit	= fuzznet_transmit,
	.poll		= fuzznet_poll,
};

static struct device fuzznet_dev = {
	.name = "net0",
	.driver_name = "fuzznet",
	.siblings = LIST_HEAD_INIT ( fuzznet_dev.siblings ),
	.children = LIST_HEAD_INIT ( fuzznet_dev.children ),
};

static inline void fuzznet_set ( struct net_device *netdev, const char *name,
			  const char *value ) {
	struct settings *settings = netdev_settings ( netdev );
	struct setting setting;
	char fullname[32];

	snprintf ( fullname, sizeof ( fullname ), "%s", name );
	if ( parse_setting_name ( fullname, autovivify_child_settings, &settings,
				  &setting ) == 0 )
		storef_setting ( settings, &setting, value );
}

/* Register and open the stub network device, or NULL */
static inline struct net_device * fuzznet_up ( void ) {
	struct net_device *netdev;

	netdev = alloc_etherdev ( 0 );
	if ( ! netdev )
		return NULL;
	netdev_init ( netdev, &fuzznet_operations );
	netdev->dev = &fuzznet_dev;
	snprintf ( netdev->name, sizeof ( netdev->name ), "%s",
		   fuzznet_dev.name );
	memcpy ( netdev->hw_addr, fuzznet_client_mac, ETH_ALEN );
	if ( register_netdev ( netdev ) != 0 ) {
		netdev_nullify ( netdev );
		netdev_put ( netdev );
		return NULL;
	}
	if ( netdev_open ( netdev ) != 0 ) {
		unregister_netdev ( netdev );
		netdev_nullify ( netdev );
		netdev_put ( netdev );
		return NULL;
	}
	return netdev;
}

static inline void fuzznet_down ( struct net_device *netdev ) {
	netdev_close ( netdev );
	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

#endif
