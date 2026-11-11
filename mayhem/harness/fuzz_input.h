/* Shared by the iPXE-side fuzz harnesses: input loading + process entry point. */
#ifndef FUZZ_INPUT_H
#define FUZZ_INPUT_H

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ipxe/init.h>
#include <ipxe/linux_api.h>

#define FUZZ_MAX_INPUT ( 1024 * 1024 )

static uint8_t fuzz_inbuf[FUZZ_MAX_INPUT];

/* Read the test case (argv[1], or stdin) and return an exact-size heap copy. */
static inline void * fuzz_read ( size_t *len ) {
	size_t used = 0;
	ssize_t got;
	void *copy;
	int fd = 0;

	if ( ( linux_argc > 1 ) &&
	     ( ( fd = linux_open ( linux_argv[1], 0 /* O_RDONLY */ ) ) < 0 ) )
		return NULL;
	while ( used < sizeof ( fuzz_inbuf ) ) {
		got = linux_read ( fd, ( fuzz_inbuf + used ),
				   ( sizeof ( fuzz_inbuf ) - used ) );
		if ( got <= 0 )
			break;
		used += got;
	}
	if ( fd > 0 )
		linux_close ( fd );
	*len = used;
	copy = malloc ( used ? used : 1 );
	if ( copy )
		memcpy ( copy, fuzz_inbuf, used );
	return copy;
}

/* Define the process entry point (replaces iPXE's own main) for a target. */
#define FUZZ_TARGET( func )						\
	__asmcall int main ( void ) {					\
		void *data;						\
		size_t len;						\
		initialise();						\
		data = fuzz_read ( &len );				\
		if ( ! data )						\
			return 1;					\
		func ( data, len );					\
		free ( data );						\
		return 0;						\
	}

#endif
