/*
 * Map iPXE's Valgrind annotations onto the AddressSanitizer poisoning
 * API.  iPXE allocates from a static heap, which ASan cannot see
 * into; its own annotations describe exactly which bytes are live.
 * Force-included into every iPXE translation unit by build.sh.
 */
#ifndef MAYHEM_ASAN_VALGRIND_H
#define MAYHEM_ASAN_VALGRIND_H

#if !defined ( __ASSEMBLER__ ) && defined ( __SANITIZE_ADDRESS__ )
#define __VALGRIND_H
#define __MEMCHECK_H

void __asan_poison_memory_region ( void const volatile *addr,
				   unsigned long size );
void __asan_unpoison_memory_region ( void const volatile *addr,
				     unsigned long size );

#define RUNNING_ON_VALGRIND 1
#define VALGRIND_MAKE_MEM_NOACCESS( addr, len ) \
	__asan_poison_memory_region ( ( addr ), ( len ) )
#define VALGRIND_MAKE_MEM_UNDEFINED( addr, len ) \
	__asan_unpoison_memory_region ( ( addr ), ( len ) )
#define VALGRIND_MAKE_MEM_DEFINED( addr, len ) \
	__asan_unpoison_memory_region ( ( addr ), ( len ) )
#define VALGRIND_MALLOCLIKE_BLOCK( addr, len, redzone, zeroed ) \
	__asan_unpoison_memory_region ( ( addr ), ( len ) )
#define VALGRIND_FREELIKE_BLOCK( addr, redzone ) do { } while ( 0 )
#define VALGRIND_GET_VBITS( addr, vbits, len ) 0
#define VALGRIND_SET_VBITS( addr, vbits, len ) 0
#endif

#endif
