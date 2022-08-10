/*
	Constant time encoding

	Written in 2014-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "base64.h"
#include <stdint.h>

#define BASE_DECODE_RANGE_1_DONT_CALL(ch, lo1, hi1) \
	/* ret = -1; */ \
	(-1) + \
	/* if (lo1 - 1 < ch && ch < hi1 + 1) */ \
	/*   ret += 1 + */ \
	/*     (ch - lo1); */ \
	(((((lo1 - 1) - /* < */ ch)  & /* && */  (ch - /* < */ (hi1 + 1))) >> 8) & \
		(1 + /* because ret = -1 */ \
			(ch - lo1)))

#define BASE_DECODE_RANGE_2_DONT_CALL(ch, lo1, hi1, lo2, hi2) \
	BASE_DECODE_RANGE_1_DONT_CALL(ch, lo1, hi1) + \
	/* if (lo2 - 1 < ch && ch < hi2 + 1) */ \
	/*   ret += 1 + */ \
	/*        (hi1 - lo1 + 1) + */ \
	/*        (ch  - lo2); */ \
	(((((lo2 - 1) - /* < */ ch)  & /* && */  (ch - /* < */ (hi2 + 1))) >> 8) & \
		(1 + /* because ret = -1 */ \
			(hi1 - lo1 + 1) + \
			(ch  - lo2)))

#define BASE_DECODE_RANGE_3_DONT_CALL(ch, lo1, hi1, lo2, hi2, lo3, hi3) \
	BASE_DECODE_RANGE_2_DONT_CALL(ch, lo1, hi1, lo2, hi2) + \
	/* if (lo3 - 1 < ch && ch < hi3 + 1) */ \
	/*   ret += 1 + */ \
	/*        + (hi1 - lo1 + 1) */ \
	/*        + (hi2 - lo2 + 1) */ \
	/*        - (ch  - lo3); */ \
	(((((lo3 - 1) - /* < */ ch)  & /* && */  (ch - /* < */ (hi3 + 1))) >> 8) & \
		(1 + /* because ret = -1 */ \
			(hi1 - lo1 + 1) + \
			(hi2 - lo2 + 1) + \
			(ch  - lo3)))

#define BASE_DECODE_RANGE_4_DONT_CALL(ch, lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4) \
	BASE_DECODE_RANGE_3_DONT_CALL(ch, lo1, hi1, lo2, hi2, lo3, hi3) + \
	/* if (lo4 - 1 < ch && ch < hi4 + 1) */ \
	/*   ret += 1 + */ \
	/*        + (hi1 - lo1 + 1) */ \
	/*        + (hi2 - lo2 + 1) */ \
	/*        + (hi3 - lo3 + 1) */ \
	/*        - (ch  - lo4); */ \
	(((((lo4 - 1) - /* < */ ch)  & /* && */  (ch - /* < */ (hi4 + 1))) >> 8) & \
		(1 + /* because ret = -1 */ \
			(hi1 - lo1 + 1) + \
			(hi2 - lo2 + 1) + \
			(hi3 - lo3 + 1) + \
			(ch  - lo4)))

#define BASE_DECODE_RANGE_5_DONT_CALL(ch, lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4, lo5, hi5) \
	BASE_DECODE_RANGE_4_DONT_CALL(ch, lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4) + \
	/* if (lo5 - 1 < ch && ch < hi5 + 1) */ \
	/*   ret += 1 + */ \
	/*        + (hi1 - lo1 + 1) */ \
	/*        + (hi2 - lo2 + 1) */ \
	/*        + (hi3 - lo3 + 1) */ \
	/*        + (hi4 - lo4 + 1) */ \
	/*        - (ch  - lo5); */ \
	(((((lo5 - 1) - /* < */ ch)  & /* && */  (ch - /* < */ (hi5 + 1))) >> 8) & \
		(1 + /* because ret = -1 */ \
			(hi1 - lo1 + 1) + \
			(hi2 - lo2 + 1) + \
			(hi3 - lo3 + 1) + \
			(hi4 - lo4 + 1) + \
			(ch  - lo5)))


#define BASE_DECODE_RANGE_1(ch, lo1, hi1) \
	(BASE_DECODE_RANGE_1_DONT_CALL( \
		((int) ((uint8_t) (ch))), \
		((int) ((uint8_t) (lo1))), ((int) ((uint8_t) (hi1)))))

#define BASE_DECODE_RANGE_2(ch, lo1, hi1, lo2, hi2) \
	(BASE_DECODE_RANGE_2_DONT_CALL( \
		((int) ((uint8_t) (ch))), \
		((int) ((uint8_t) (lo1))), ((int) ((uint8_t) (hi1))), \
		((int) ((uint8_t) (lo2))), ((int) ((uint8_t) (hi2)))))

#define BASE_DECODE_RANGE_3(ch, lo1, hi1, lo2, hi2, lo3, hi3) \
	(BASE_DECODE_RANGE_3_DONT_CALL( \
		((int) ((uint8_t) (ch))), \
		((int) ((uint8_t) (lo1))), ((int) ((uint8_t) (hi1))), \
		((int) ((uint8_t) (lo2))), ((int) ((uint8_t) (hi2))), \
		((int) ((uint8_t) (lo3))), ((int) ((uint8_t) (hi3)))))

#define BASE_DECODE_RANGE_4(ch, lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4) \
	(BASE_DECODE_RANGE_4_DONT_CALL( \
		((int) ((uint8_t) (ch))), \
		((int) ((uint8_t) (lo1))), ((int) ((uint8_t) (hi1))), \
		((int) ((uint8_t) (lo2))), ((int) ((uint8_t) (hi2))), \
		((int) ((uint8_t) (lo3))), ((int) ((uint8_t) (hi3))), \
		((int) ((uint8_t) (lo4))), ((int) ((uint8_t) (hi4)))))

#define BASE_DECODE_RANGE_5(ch, lo1, hi1, lo2, hi2, lo3, hi3, lo4, hi4, lo5, hi5) \
	(BASE_DECODE_RANGE_5_DONT_CALL( \
		((int) ((uint8_t) (ch))), \
		((int) ((uint8_t) (lo1))), ((int) ((uint8_t) (hi1))), \
		((int) ((uint8_t) (lo2))), ((int) ((uint8_t) (hi2))), \
		((int) ((uint8_t) (lo3))), ((int) ((uint8_t) (hi3))), \
		((int) ((uint8_t) (lo4))), ((int) ((uint8_t) (hi4))), \
		((int) ((uint8_t) (lo5))), ((int) ((uint8_t) (hi5)))))


// ************************
// *** Helper Functions ***
// ************************

// Base64 character set:
// [.-9][A-Z][a-z]

/**
 * Decode a base64 character.
 *
 * @param src - A base64 character.
 * @return On success the decoded value, otherwise negative number on error.
 */
static inline int base64Decode6BitsDotSlashOrdered(char src)
{
	return BASE_DECODE_RANGE_3(src, '.','9',  'A','Z',  'a','z');
}

/**
 * Decode 4 base64 characters into 3 bytes of data.
 *
 * @param dest - 3 bytes of data.
 * @param src - 4 base64 characters.
 * @return On success a positive number, otherwise negative number on error.
 */
static inline int base64Decode3BytesDotSlashOrdered(uint8_t dest[3], const char src[4])
{
	int c0 = base64Decode6BitsDotSlashOrdered(src[0]);
	int c1 = base64Decode6BitsDotSlashOrdered(src[1]);
	int c2 = base64Decode6BitsDotSlashOrdered(src[2]);
	int c3 = base64Decode6BitsDotSlashOrdered(src[3]);

	dest[0] = (uint8_t) ((c0 << 2) | (c1 >> 4));
	dest[1] = (uint8_t) ((c1 << 4) | (c2 >> 2));
	dest[2] = (uint8_t) ((c2 << 6) |  c3      );
	return c0 | c1 | c2 | c3;
}

/**
 * Encode a base64 character.
 *
 * @param src - 6 bits of data.
 * @return A base64 character.
 */
static inline char base64Encode6BitsDotSlashOrdered(int src)
{
	src += '.';

	// if  ( '9' < src      ) src += 'A' - ('9' + 1);
	src += (('9' - src) >> 9) &     ('A' - ('9' + 1));

	// if  ( 'Z' < src      ) src += 'a' - ('Z' + 1);
	src += (('Z' - src) >> 9) &     ('a' - ('Z' + 1));

	return (char) src;
}

/**
 * Encode 3 bytes of data into 4 base64 characters.
 *
 * @param dest - 4 base64 characters.
 * @param src - 3 bytes of data.
 */
static inline void base64Encode3BytesDotSlashOrdered(char dest[4], const uint8_t src[3])
{
	int b0 = src[0];
	int b1 = src[1];
	int b2 = src[2];

	dest[0] = base64Encode6BitsDotSlashOrdered(              b0 >> 2       );
	dest[1] = base64Encode6BitsDotSlashOrdered(((b0 << 4) | (b1 >> 4)) & 63);
	dest[2] = base64Encode6BitsDotSlashOrdered(((b1 << 2) | (b2 >> 6)) & 63);
	dest[3] = base64Encode6BitsDotSlashOrdered(  b2                    & 63);
}


// **********************
// *** Main Functions ***
// **********************

/**
 * Find the base64 string's decoded size.
 *
 * @param src - Base64 string.
 * @param srcSize - Base64 string's size.
 * @param flags - Decoding flags.
 * @return On success the base64 string's decoded size, otherwise SIZE_MAX.
 */
size_t base64DecodedSize(const char *src, size_t srcSize, int flags)
{
	size_t size = 0;

	if (srcSize % 4 == 1 || (srcSize % 4 != 0 && (flags & BASE64_DECODE_FLAG_IGNORE_NO_PAD) == 0))
	{
		size = SIZE_MAX;
	}
	else if (srcSize > 0)
	{
		if (srcSize % 4 == 0)
		{
			// if (src[srcSize - 1] == '=') { srcSize--; if (src[srcSize - 2] == '=') srcSize--; }
			int ch   = (uint8_t) src[srcSize - 1];
			int pad2 = ((-(ch ^ '=')) >> 8) + 1;
			ch       = (uint8_t) src[srcSize - 2];
			int pad3 = ((-(ch ^ '=')) >> 8) + 1;
			srcSize  -= pad2 + pad3;
			// if (pad3 == 0 && pad2 == 1) size = SIZE_MAX;
			// *** Assumption *** "SIZE_MAX == (1 << n) - 1"
			size = (pad3 - pad2) | SIZE_MAX;
		}
		// size = 3 * (srcSize / 4)
		// if (srcSize % 4 != 0) size += srcSize % 4 - 1;
		// *** Assumption *** "SIZE_MAX == (1 << n) - 1"
		size |= 3 * (srcSize / 4) + srcSize % 4 - ((-(int) (srcSize % 4)) & 1);
	}
	return size;
}

/**
 * Encodes a base64 string with a character set of "./[0-9][A-Z][a-z]". Terminates string with null character.
 *
 * @param dest - Base64 string.
 * @param src - Data.
 * @param srcSize - Size of data.
 * @param flags - Encoding flags.
 * @return Number of characters written.
 */
size_t base64Encode(char *dest, const void *src, size_t srcSize, int flags)
{
	char *dest_ = dest;

	for (; srcSize >= 3; srcSize -= 3)
	{
		base64Encode3BytesDotSlashOrdered(dest, (const uint8_t*) src);
		dest += 4;
		src   = (const uint8_t*) src + 3;
	}
	if (srcSize > 0)
	{
		unsigned int b0 = ((const uint8_t*) src)[0];
		unsigned int b1 = 0;

		if (srcSize > 1)
		{
			b1 = ((const uint8_t*) src)[1];
		}
		dest[0] = base64Encode6BitsDotSlashOrdered(              b0 >> 2       );
		dest[1] = base64Encode6BitsDotSlashOrdered(((b0 << 4) | (b1 >> 4)) & 63);
		if (srcSize > 1)
		{
			dest[2] = base64Encode6BitsDotSlashOrdered(( b1 << 2             ) & 63);
		}

		dest += srcSize + 1;
		if ((flags & BASE64_ENCODE_FLAG_NO_PAD) == 0)
		{
			*dest = '=';
			dest++;
			if (srcSize == 1)
			{
				*dest = '=';
				dest++;
			}
		}
	}

	*dest = 0;
	return dest - dest_;
}

/**
 * Decodes a base64 string with a character set of "./[0-9][A-Z][a-z]".
 *
 * @param dest - Data.
 * @param src - Base64 string.
 * @param srcSize - Size of base64 string.
 * @param flags - Decoding flags.
 * @return On success zero, otherwise non-zero.
 */
int base64Decode(void *dest, const char *src, size_t srcSize, int flags)
{
	int err = 0;

	if (srcSize % 4 == 1 || (srcSize % 4 != 0 && (flags & BASE64_DECODE_FLAG_IGNORE_NO_PAD) == 0))
	{
		err = -1;
	}
	else if (srcSize > 0)
	{
		for (; srcSize > 4; srcSize -= 4)
		{
			err |= base64Decode3BytesDotSlashOrdered((uint8_t*) dest, src);
			dest = (uint8_t*) dest + 3;
			src += 4;
		}

		// At this point srcSize is 2, 3, or 4

		int c0 = base64Decode6BitsDotSlashOrdered(src[0]);
		int c1 = base64Decode6BitsDotSlashOrdered(src[1]);
		int c2 = 0;
		int c3 = 0;
		err |= c0 | c1;

		if (srcSize > 3)
		{
			// if (src[3] == '=') { srcSize--; if (src[2] == '=') srcSize--; }
			int ch   = (uint8_t) src[2];
			int pad2 = ((-(ch ^ '=')) >> 8) + 1;
			ch       = (uint8_t) src[3];
			int pad3 = ((-(ch ^ '=')) >> 8) + 1;
			srcSize  -= pad2 + pad3;

			// if (src[2] != '=' || src[3] != '=') c2 = base64Decode6BitsDotSlashOrdered(src[2])
			// if (src[3] != '=')                  c3 = base64Decode6BitsDotSlashOrdered(src[3])
			c2 = base64Decode6BitsDotSlashOrdered(src[2]) & ~(-(pad2 | pad3));
			c3 = base64Decode6BitsDotSlashOrdered(src[3]) & ~(-pad3);
			err |= c2 | c3;

			// Not exactly constant time but close
			// Also it doesn't matter since it's length
			// dest[srcSize >= 3 ? 1 : 0] = (uint8_t) ((c1 << 4) | (c2 >> 2));
			// dest[srcSize >= 4 ? 2 : 0] = (uint8_t) ((c2 << 6) |  c3      );
			((uint8_t*) dest)[1 & ((2 - srcSize) >> 1)] = (uint8_t) ((c1 << 4) | (c2 >> 2));
			((uint8_t*) dest)[2 & ((3 - srcSize) >> 1)] = (uint8_t) ((c2 << 6) |  c3      );
		}
		else if (srcSize == 3)
		{
			c2 = base64Decode6BitsDotSlashOrdered(src[2]);
			err |= c2;
			((uint8_t*) dest)[1] = (uint8_t) ((c1 << 4) | (c2 >> 2));
		}
		((uint8_t*) dest)[0] = (uint8_t) ((c0 << 2) | (c1 >> 4));

		if ((flags & BASE64_DECODE_FLAG_IGNORE_BAD_PAD) == 0)
		{
			// if (srcSize < 3 && (c1 & 0x0f) != 0) err = 1;
			err |= (srcSize - 3) & (-(c1 & 0x0f));
			// if (srcSize < 4 && (c2 & 0x03) != 0) err = 1;
			err |= (srcSize - 4) & (-(c2 & 0x03)); // Note `c2` is 0 when srcSize is 2
		}
	}
	return (err >> 8) & 1;
}
