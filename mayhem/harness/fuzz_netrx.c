FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdio.h>
#include <ipxe/device.h>
#include <ipxe/netdevice.h>
#include <ipxe/if_ether.h>
#include <ipxe/ethernet.h>
#include <ipxe/iobuf.h>
#include <ipxe/process.h>
#include <ipxe/settings.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();

static int fuzznet_open ( struct net_device *netdev __unused ) {
	return 0;
}

static void fuzznet_close ( struct net_device *netdev __unused ) {
}

static int fuzznet_transmit ( struct net_device *netdev,
			      struct io_buffer *iobuf ) {
	netdev_tx_complete ( netdev, iobuf );
	return 0;
}

static void fuzznet_poll ( struct net_device *netdev __unused ) {
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

static void fuzznet_set ( struct net_device *netdev, const char *name,
			  const char *value ) {
	struct settings *settings = netdev_settings ( netdev );
	struct setting setting;
	char fullname[32];

	snprintf ( fullname, sizeof ( fullname ), "%s", name );
	if ( parse_setting_name ( fullname, autovivify_child_settings, &settings,
				  &setting ) == 0 )
		storef_setting ( settings, &setting, value );
}

/* Deliver a raw Ethernet frame to a configured network device. */
static void fuzz_netrx ( const void *data, size_t len ) {
	static const uint8_t hwaddr[ETH_ALEN] =
		{ 0x52, 0x54, 0x00, 0x59, 0xba, 0xc9 };
	struct net_device *netdev;
	struct io_buffer *iobuf;
	unsigned int i;

	netdev = alloc_etherdev ( 0 );
	if ( ! netdev )
		return;
	netdev_init ( netdev, &fuzznet_operations );
	netdev->dev = &fuzznet_dev;
	snprintf ( netdev->name, sizeof ( netdev->name ), "%s",
		   fuzznet_dev.name );
	memcpy ( netdev->hw_addr, hwaddr, ETH_ALEN );
	if ( register_netdev ( netdev ) != 0 ) {
		netdev_nullify ( netdev );
		netdev_put ( netdev );
		return;
	}
	if ( netdev_open ( netdev ) == 0 ) {
		fuzznet_set ( netdev, "net0/ip", "192.168.0.1" );
		fuzznet_set ( netdev, "net0/netmask", "255.255.255.0" );
		fuzznet_set ( netdev, "net0/gateway", "192.168.0.254" );
		iobuf = alloc_iob ( len ? len : 1 );
		if ( iobuf ) {
			memcpy ( iob_put ( iobuf, len ), data, len );
			netdev_rx ( netdev, iobuf );
			for ( i = 0 ; i < 4 ; i++ )
				step();
		}
		netdev_close ( netdev );
	}
	unregister_netdev ( netdev );
	netdev_nullify ( netdev );
	netdev_put ( netdev );
}

FUZZ_TARGET ( fuzz_netrx )
