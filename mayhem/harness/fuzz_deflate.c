FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/deflate.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();
REQUIRE_OBJECT ( deflate );

/*
 * Inflate a DEFLATE stream.  The first byte picks the format (raw or
 * ZLIB) and the second the input fragment size, so that decompression
 * is resumed at arbitrary points.
 */
static void fuzz_deflate ( const void *data, size_t len ) {
	const uint8_t *bytes = data;
	struct deflate *deflate;
	struct deflate_chunk out;
	size_t frag;
	size_t offset;
	size_t this_len;
	void *buf;

	if ( len < 2 )
		return;
	frag = ( bytes[1] ? bytes[1] : 1 );
	bytes += 2;
	len -= 2;
	deflate = malloc ( sizeof ( *deflate ) );
	buf = malloc ( 65536 );
	if ( deflate && buf ) {
		deflate_init ( deflate, ( ( bytes[-2] & 1 ) ? DEFLATE_ZLIB :
					  DEFLATE_RAW ) );
		deflate_chunk_init ( &out, buf, 0, 65536 );
		for ( offset = 0 ; offset < len ; offset += this_len ) {
			this_len = ( len - offset );
			if ( this_len > frag )
				this_len = frag;
			if ( deflate_inflate ( deflate, ( bytes + offset ),
					       this_len, &out ) != 0 )
				break;
		}
	}
	free ( buf );
	free ( deflate );
}

FUZZ_TARGET ( fuzz_deflate )
