FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/tls.h>
#include <ipxe/xfer.h>
#include "fuzz_net.h"

PROVIDE_REQUIRING_SYMBOL();

/*
 * Run a TLS client handshake against a server whose bytes are the input: the client sends its
 * ClientHello into a stub transport, then the input is delivered to it as the TLS record stream.
 */
static void fuzz_tls ( const void *data, size_t len ) {
	struct interface app;
	struct interface transport;

	srandom ( 1 );
	intf_init ( &app, &fuzznet_sink_desc, NULL );
	intf_init ( &transport, &fuzznet_sink_desc, NULL );
	intf_plug_plug ( &app, &transport );
	if ( add_tls ( &app, "boot.example.com", NULL, NULL ) == 0 ) {
		fuzznet_steps();
		xfer_deliver_raw ( &transport, data, len );
		fuzznet_steps();
	}
	intf_shutdown ( &app, 0 );
	intf_shutdown ( &transport, 0 );
}

FUZZ_TARGET ( fuzz_tls )
