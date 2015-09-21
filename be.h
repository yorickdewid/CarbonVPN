#ifndef BE_H
#define BE_H

#include <endian.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define swap16(val) val
#define swap32(val) val
#define swap64(val) val
#else

/* Swap 2 byte, 16 bit */
#define swap16(val) \
 ( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )

/* Swap 4 byte, 32 bit */
#define swap32(val) \
 ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
   (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )

/* Swap 6 byte, 64 bit */
#define swap64(val) \
 ( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
   (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
   (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
   (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )
#endif

#endif // BE_H
