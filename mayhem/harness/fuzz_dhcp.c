FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/dhcp.h>
#include <ipxe/dhcppkt.h>
#include <ipxe/dhcpopts.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();

/* Walk and edit the options of a DHCP packet. */
static void fuzz_dhcp ( const void *data, size_t len ) {
	struct dhcp_packet dhcppkt;
	uint8_t value[300];
	unsigned int tag;
	int rc;

	if ( len < sizeof ( struct dhcphdr ) )
		return;
	dhcppkt_init ( &dhcppkt, ( struct dhcphdr * ) data, len );
	for ( tag = 1 ; tag < 256 ; tag++ ) {
		rc = dhcppkt_fetch ( &dhcppkt, tag, value, sizeof ( value ) );
		if ( rc > 1 )
			dhcppkt_store ( &dhcppkt, tag, value, ( rc / 2 ) );
	}
	dhcppkt_fetch ( &dhcppkt, DHCP_EB_ENCAP, value, sizeof ( value ) );
	dhcppkt_store ( &dhcppkt, DHCP_EB_BUS_ID, "\0\1\2\3\4\5", 6 );
	dhcppkt_store ( &dhcppkt, 0, NULL, 0 );
}

FUZZ_TARGET ( fuzz_dhcp )
