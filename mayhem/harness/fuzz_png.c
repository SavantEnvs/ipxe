FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/image.h>
#include <ipxe/pixbuf.h>
#include <ipxe/png.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();
REQUIRE_OBJECT ( png );

/* Decode a PNG image into a pixel buffer. */
static void fuzz_png ( const void *data, size_t len ) {
	struct image *image;
	struct pixel_buffer *pixbuf;

	image = image_memory ( "fuzz.png", data, len );
	if ( ! image )
		return;
	if ( ( image->type == &png_image_type ) &&
	     ( image_pixbuf ( image, &pixbuf ) == 0 ) )
		pixbuf_put ( pixbuf );
	unregister_image ( image );
}

FUZZ_TARGET ( fuzz_png )
