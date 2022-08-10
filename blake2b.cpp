/*
	bscrypt

	Written in 2019-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "blake2b.h"
#include "common.h"
#include "string.h"

#ifdef USE_VENDER_BLAKE2B

/**
 * Calculates a BLAKE2b hash with inputs as uint64_t. Output is standard BLAKE2b bytes.
 *
 * @param uint64_t hash[8]   - The calculated hash.
 * @param uint64_t settings  - 0x0101kknn, kk being key length and nn being output size.
 * @param const uint64_t *in - Data to be hashed.
 * @param size_t inSize      - Size of data.
 */
void blake2b_nativeIn(void *out, size_t outSize, const uint64_t *in, size_t inSize)
{
	blake2b_ctx ctx;
	uint8_t     block[128];

	if (outSize > 64)
	{
		outSize = 64;
	}
	blake2b_init(&ctx, outSize);
	for (; inSize > 128; inSize -= 128)
	{
		for (size_t i = 0; i < 16; i++)
		{
			block[8 * i + 0] = (uint8_t) (in[i]);
			block[8 * i + 1] = (uint8_t) (in[i] >>  8);
			block[8 * i + 2] = (uint8_t) (in[i] >> 16);
			block[8 * i + 3] = (uint8_t) (in[i] >> 24);
			block[8 * i + 4] = (uint8_t) (in[i] >> 32);
			block[8 * i + 5] = (uint8_t) (in[i] >> 40);
			block[8 * i + 6] = (uint8_t) (in[i] >> 48);
			block[8 * i + 7] = (uint8_t) (in[i] >> 56);
		}
		blake2b_update(&ctx, block, 128);
		in += 16;
	}
	for (size_t i = 0; i < inSize; i++)
	{
		block[i] = (uint8_t) (in[i / 8] >> (8 * (i % 8)));
	}
	blake2b_update(&ctx, block, inSize);
	blake2b_finish(&ctx, out);

	// Clear
	secureClearMemory(block, sizeof(block));
}

/**
 * Calculates a BLAKE2b hash with inputs and outputs as uint64_t. This is an endian free function.
 *
 * @param uint64_t out[8]    - The calculated hash.
 * @param const uint64_t *in - Data to be hashed.
 * @param size_t inSize      - Size of data.
 */
void blake2b_nativeInOut(uint64_t out[8], const uint64_t *in, size_t inSize)
{
	uint8_t hash[8];

	// Hash
	blake2b_nativeIn(hash, 64, in, inSize);

	// Output
	for (size_t i = 0; i < 8; i++)
	{
		out[i] =
			(((uint64_t) hash[8 * i + 0])      ) |
			(((uint64_t) hash[8 * i + 1]) <<  8) |
			(((uint64_t) hash[8 * i + 2]) << 16) |
			(((uint64_t) hash[8 * i + 3]) << 24) |
			(((uint64_t) hash[8 * i + 4]) << 32) |
			(((uint64_t) hash[8 * i + 5]) << 40) |
			(((uint64_t) hash[8 * i + 6]) << 48) |
			(((uint64_t) hash[8 * i + 7]) << 56);
	}

	// Clear
	secureClearMemory(hash, sizeof(hash));
}

#else

const uint64_t BLAKE2B_IV[8] = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

#define ROTR64(n, s) (((n) >> (s)) | ((n) << (64 - (s))))

static inline void blake2b_mix(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d, uint64_t m0, uint64_t m1)
{
	a += b + m0; d = ROTR64(d ^ a, 32);
	c += d;      b = ROTR64(b ^ c, 24);
	a += b + m1; d = ROTR64(d ^ a, 16);
	c += d;      b = ROTR64(b ^ c, 63);
}

/**
 * Calcualtes a BLAKE2b block.
 *
 * @param uint64_t state[8]      - The current state.
 * @param const uint64_t msg[16] - The message block to hash.
 * @param uint64_t bytesLo       - Bytes hashed.
 * @param uint64_t bytesHi       - Bytes hashed.
 * @param uint64_t last          - For the last block set to 0xffffffffffffffff, otherwise 0.
 */
static void blake2b_block(uint64_t state[8], const uint64_t msg[16], uint64_t bytesLo, uint64_t bytesHi, uint64_t last)
{
	const int sigm[16 * 12] = {
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
		11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
		 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
		 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
		 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
		12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
		13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
		 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
		10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0,
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3};

	uint64_t block[16];

	memcpy(block,     state,       8 * sizeof(uint64_t));
	memcpy(block + 8, BLAKE2B_IV, sizeof(BLAKE2B_IV));
	block[12] ^= bytesLo;
	block[13] ^= bytesHi;
	block[14] ^= last;
	for (int i = 0; i < 192; i += 16) // 192 = 16 * 12
	{
		blake2b_mix(block[0], block[4], block[ 8], block[12], msg[sigm[i +  0]], msg[sigm[i +  1]]);
		blake2b_mix(block[1], block[5], block[ 9], block[13], msg[sigm[i +  2]], msg[sigm[i +  3]]);
		blake2b_mix(block[2], block[6], block[10], block[14], msg[sigm[i +  4]], msg[sigm[i +  5]]);
		blake2b_mix(block[3], block[7], block[11], block[15], msg[sigm[i +  6]], msg[sigm[i +  7]]);

		blake2b_mix(block[0], block[5], block[10], block[15], msg[sigm[i +  8]], msg[sigm[i +  9]]);
		blake2b_mix(block[1], block[6], block[11], block[12], msg[sigm[i + 10]], msg[sigm[i + 11]]);
		blake2b_mix(block[2], block[7], block[ 8], block[13], msg[sigm[i + 12]], msg[sigm[i + 13]]);
		blake2b_mix(block[3], block[4], block[ 9], block[14], msg[sigm[i + 14]], msg[sigm[i + 15]]);
	}

	state[0] ^= block[0] ^ block[ 8];
	state[1] ^= block[1] ^ block[ 9];
	state[2] ^= block[2] ^ block[10];
	state[3] ^= block[3] ^ block[11];
	state[4] ^= block[4] ^ block[12];
	state[5] ^= block[5] ^ block[13];
	state[6] ^= block[6] ^ block[14];
	state[7] ^= block[7] ^ block[15];
}

/**
 * Initializes a BLAKE2b context.
 *
 * @param blake2b_ctx *ctx - The BLAKE2b context.
 * @param size_t outSize   - The output size for the BLAKE2b hash.
 */
void blake2b_init(blake2b_ctx *ctx, size_t outSize)
{
	memcpy(ctx->state, BLAKE2B_IV, sizeof(BLAKE2B_IV));
	ctx->state[0] ^= 0x01010000 ^ outSize;
	memset(ctx->block, 0, sizeof(ctx->block));
	ctx->bytesLo = 0;
	ctx->bytesHi = 0;
	ctx->outSize = outSize;
}

void blake2b_update(blake2b_ctx *ctx, const void *msg, size_t msgSize)
{
	if (msgSize != 0)
	{
		uint64_t bytesLo = ctx->bytesLo;
		uint64_t bytesHi = ctx->bytesHi;
		const uint8_t *msg_ = (const uint8_t*) msg;
		size_t offset = bytesLo % 128;
		size_t blockLeft = 128 - offset;

		// Has full block
		if (offset == 0 && (bytesLo != 0 || bytesHi != 0))
		{
			blockLeft = 0;
		}

		// Can surpass full block
		while (msgSize > blockLeft)
		{
			memcpy(((uint8_t*) (ctx->block)) + offset, msg_, blockLeft);

#ifdef ARC_BIG_ENDIAN
			for (int i = 0; i < 16; i++)
			{
				uint64_t tmp = ctx->block[i];
				ctx->block[i] = SWAP_ENDIAN_64(tmp);
			}
#endif
			bytesLo += blockLeft;
			if (bytesLo < blockLeft)
			{
				bytesHi++;
			}
			blake2b_block(ctx->state, ctx->block, bytesLo, bytesHi, 0);

			msg_ += blockLeft;
			msgSize -= blockLeft;
			offset = 0;
			blockLeft = 128;
		}

		// Can't surpass full block
		if (msgSize != 0)
		{
			memcpy(((uint8_t*) (ctx->block)) + offset, msg_, msgSize);

			bytesLo += msgSize;
			if (bytesLo < msgSize)
			{
				bytesHi++;
			}
		}
		ctx->bytesLo = bytesLo;
		ctx->bytesHi = bytesHi;
	}
}

/**
 * Outputs a BLAKE2b hash.
 *
 * @param blake2b_ctx *ctx - The BLAKE2b context.
 * @param void *out        - The calculated hash.
 */
void blake2b_finish(blake2b_ctx *ctx, void *out)
{
	// Last block
#ifdef ARC_BIG_ENDIAN
	for (int i = 0; i < 16; i++)
	{
		uint64_t tmp = ctx->block[i];
		ctx->block[i] = SWAP_ENDIAN_64(tmp);
	}
#endif
	blake2b_block(ctx->state, ctx->block, ctx->bytesLo, ctx->bytesHi, UINT64_C(0xffffffffffffffff));

	// Output
	size_t outSize = ctx->outSize;
	for (size_t i = 0; i < outSize; i++)
	{
		((uint8_t*) out)[i] = (uint8_t) (ctx->state[i / 8]);
		ctx->state[i / 8] >>= 8;
	}

	// Clean up
	blake2b_init(ctx, outSize);
}

/**
 * Calculates a BLAKE2b hash with inputs and outputs as uint64_t. This is an endian free function.
 *
 * @param uint64_t hash[8]   - The calculated hash.
 * @param uint64_t settings  - 0x0101kknn, kk being key length and nn being output size.
 * @param const uint64_t *in - Data to be hashed.
 * @param size_t inSize      - Size of data.
 */
static void blake2b_native(uint64_t hash[8], uint64_t settings, const uint64_t *in, size_t inSize)
{
	uint64_t block[16];
	uint64_t bytes = 0;
	size_t   i;

	memcpy(hash, BLAKE2B_IV, sizeof(BLAKE2B_IV));
	hash[0] ^= settings;

	for (; inSize > 128; inSize -= 128)
	{
		bytes += 128;
		blake2b_block(hash, in, bytes, 0, 0);
		in += 16;
	}
	for (i = 0; i < (inSize + 7) / 8; i++)
	{
		block[i] = in[i];
	}
	for (; i < 16; i++)
	{
		block[i] = 0;
	}
	blake2b_block(hash, block, bytes + inSize, 0, UINT64_C(0xffffffffffffffff));

	// Clear
	secureClearMemory(block, sizeof(block));
}

/**
 * Calculates a BLAKE2b hash with inputs as uint64_t. Output is standard BLAKE2b bytes.
 *
 * @param uint64_t hash[8]   - The calculated hash.
 * @param uint64_t settings  - 0x0101kknn, kk being key length and nn being output size.
 * @param const uint64_t *in - Data to be hashed.
 * @param size_t inSize      - Size of data.
 */
void blake2b_nativeIn(void *out, size_t outSize, const uint64_t *in, size_t inSize)
{
	uint64_t hash[8];

	// Hash
	if (outSize > 64)
	{
		outSize = 64;
	}
	blake2b_native(hash, 0x01010000 ^ outSize, in, inSize);

	// Output
	for (size_t i = 0; i < outSize; i++)
	{
		((uint8_t*) out)[i] = (uint8_t) (hash[i / 8]);
		hash[i / 8] >>= 8;
	}

	// Clear
	secureClearMemory(hash, sizeof(hash));
}

/**
 * Calculates a BLAKE2b hash with inputs and outputs as uint64_t. This is an endian free function.
 *
 * @param uint64_t out[8]    - The calculated hash.
 * @param const uint64_t *in - Data to be hashed.
 * @param size_t inSize      - Size of data.
 */
void blake2b_nativeInOut(uint64_t out[8], const uint64_t *in, size_t inSize)
{
	blake2b_native(out, 0x01010040, in, inSize);
}

#endif
