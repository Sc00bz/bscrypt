/*
	bscrypt

	Written in 2019-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "notblake2b.h"

#define ROTR64(n, s) (((n) >> (s)) | ((n) << (64 - (s))))

/**
 * Not a BLAKE2b mix calculation. There is no message and the rotates were changed from
 * 32,24,16,63 to 8,1,16,11,40,32. These were found to give a faster mix by a program
 * that checked 2 any rotates; 3 byte rotates; and 1, 32 bit rotate. This was picked
 * out of several equivalent ones because it looked similar to the "best" 4 rotates.
 * These are 8,1,24,32 that are 1 any rotate; 2 byte rotates; and 1, 32 bit rotate.
 * Related: https://twitter.com/Sc00bzT/status/1461894336052973573
 *
 * I went with the 6 rotates because it mixed faster. I was going to do either:
 *  - 2 rounds of 6 rotates
 *  - 3 rounds of 4 rotates
 *
 * Oh "3 rounds of 4 rotates" has a "coverage" of 87.5% and I believe "2 rounds of 6
 * rotates" has a "coverage" of 100%. I need to check this it's been a almost a year
 * since I looked at the data. "Coverage" is the percent of bits from the block that
 * have affected other bits. You need 1,024 variables representing the 1,024 bits in
 * the block. Each variable has 1,024 bits representing which bit from the block has
 * influenced its value. You rotate those and OR them together instead of add and XOR.
 * Then count the bits that are set. This may not be the best way to check for the best
 * rotates. Also addition influences higher bits which this doesn't check for.
 *
 * @param uint64_t &a - Input/output "a"
 * @param uint64_t &b - Input/output "b"
 * @param uint64_t &c - Input/output "c"
 * @param uint64_t &d - Input/output "d"
 */
static inline void notBlake2b_mix(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d)
{
	// 8, 1, 24, 32
	// 8, 1, 16, 11, 40, 32
	a += b; d = ROTR64(d ^ a,  8);
	c += d; b = ROTR64(b ^ c,  1);
	a += b; d = ROTR64(d ^ a, 16);
	c += d; b = ROTR64(b ^ c, 11);
	a += b; d = ROTR64(d ^ a, 40);
	c += d; b = ROTR64(b ^ c, 32);
}

/**
 * Not a BLAKE2b block calculation.
 *
 * @param uint64_t block[16] - Input/output block.
 */
void notBlake2b_block(uint64_t block[16])
{
	for (int i = 0; i < 2; i++)
	{
		notBlake2b_mix(block[0], block[4], block[ 8], block[12]);
		notBlake2b_mix(block[1], block[5], block[ 9], block[13]);
		notBlake2b_mix(block[2], block[6], block[10], block[14]);
		notBlake2b_mix(block[3], block[7], block[11], block[15]);

		notBlake2b_mix(block[0], block[5], block[10], block[15]);
		notBlake2b_mix(block[1], block[6], block[11], block[12]);
		notBlake2b_mix(block[2], block[7], block[ 8], block[13]);
		notBlake2b_mix(block[3], block[4], block[ 9], block[14]);
	}
}
