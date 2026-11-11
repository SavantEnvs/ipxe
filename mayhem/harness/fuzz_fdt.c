FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/fdt.h>
#include "fuzz_input.h"

PROVIDE_REQUIRING_SYMBOL();

/* Parse a flattened device tree and walk its structure block. */
static void fuzz_fdt ( const void *data, size_t len ) {
	struct fdt fdt;
	struct fdt_descriptor desc;
	unsigned int offset;
	unsigned int parent;
	uint64_t region;
	unsigned int steps = 0;

	if ( fdt_parse ( &fdt, ( struct fdt_header * ) data, len ) != 0 )
		return;
	offset = 0;
	while ( ( fdt_describe ( &fdt, offset, &desc ) == 0 ) &&
		( steps++ < 100000 ) ) {
		fdt_parent ( &fdt, offset, &parent );
		fdt_reg ( &fdt, offset, &region );
		fdt_phandle ( &fdt, offset );
		offset = desc.next;
	}
	fdt_path ( &fdt, "/chosen", &offset );
	fdt_path ( &fdt, "/soc/ethernet@0", &offset );
	fdt_alias ( &fdt, "ethernet0", &offset );
}

FUZZ_TARGET ( fuzz_fdt )
