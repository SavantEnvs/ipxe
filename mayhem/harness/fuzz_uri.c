FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/uri.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();

/*
 * Parse URIs.  The input is NUL-terminated and split at the first
 * newline into a base URI and a relative reference to resolve.
 */
static void fuzz_uri ( const void *data, size_t len ) {
	char *str = malloc ( len + 1 );
	char *rel;
	struct uri *base;
	struct uri *relative;
	struct uri *resolved;
	char *formatted;
	char buf[64];

	if ( ! str )
		return;
	memcpy ( str, data, len );
	str[len] = '\0';
	rel = strchr ( str, '\n' );
	if ( rel )
		*rel++ = '\0';
	base = parse_uri ( str );
	if ( base ) {
		formatted = format_uri_alloc ( base );
		free ( formatted );
		format_uri ( base, buf, sizeof ( buf ) );
		uri_port ( base, 80 );
		if ( rel ) {
			relative = parse_uri ( rel );
			if ( relative ) {
				resolved = resolve_uri ( base, relative );
				if ( resolved ) {
					formatted = format_uri_alloc ( resolved );
					free ( formatted );
					uri_put ( resolved );
				}
				uri_put ( relative );
			}
			free ( resolve_path ( str, rel ) );
		}
		uri_put ( base );
	}
	uri_decode ( str, buf, sizeof ( buf ) );
	free ( str );
}

FUZZ_TARGET ( fuzz_uri )
