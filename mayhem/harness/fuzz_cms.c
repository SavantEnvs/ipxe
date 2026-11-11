FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/image.h>
#include <ipxe/cms.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();

/* Parse a CMS (PKCS#7) signed or enveloped message and verify it. */
static void fuzz_cms ( const void *data, size_t len ) {
	struct image *image;
	struct image *payload;
	struct cms_message *cms;

	image = image_memory ( "fuzz.cms", data, len );
	if ( ! image )
		return;
	if ( cms_message ( image, &cms ) == 0 ) {
		payload = image_memory ( "payload", "fuzz", 4 );
		if ( payload ) {
			cms_verify ( cms, payload, "example.com", 1700000000,
				     NULL, NULL );
			unregister_image ( payload );
		}
		cms_put ( cms );
	}
	unregister_image ( image );
}

FUZZ_TARGET ( fuzz_cms )
