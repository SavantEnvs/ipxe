FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/x509.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();

/* Parse a DER-encoded X.509 certificate and query it. */
static void fuzz_x509 ( const void *data, size_t len ) {
	struct x509_certificate *cert;
	struct x509_chain *chain;

	if ( x509_certificate ( data, len, &cert ) != 0 )
		return;
	x509_name ( cert );
	x509_check_name ( cert, "www.example.com" );
	x509_check_name ( cert, "192.0.2.1" );
	x509_check_time ( cert, 1700000000 );
	x509_check_issuer ( cert, cert );
	chain = x509_alloc_chain();
	if ( chain ) {
		if ( x509_append ( chain, cert ) == 0 )
			x509_validate_chain ( chain, 1700000000, NULL, NULL );
		x509_chain_put ( chain );
	}
	x509_put ( cert );
}

FUZZ_TARGET ( fuzz_x509 )
