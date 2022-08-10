/*
	bscrypt

	Written in 2019-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#pragma once

#include <stdint.h>

#ifdef USE_VENDER_BLAKE2B

typedef insert_blake2b_ctx blake2b_ctx;
#define blake2b_init(ctx, outSize)         insert_blake2b_init_func(ctx, outSize)
#define blake2b_update(ctx, msg, msgSize)  insert_blake2b_update_func(ctx, msg, msgSize)
#define blake2b_finish(ctx, out)           insert_blake2b_finish_func(ctx, out)

#else

struct blake2b_ctx
{
	uint64_t state[8];
	uint64_t block[16];
	uint64_t bytesLo;
	uint64_t bytesHi;
	size_t   outSize;
};

void blake2b_init(blake2b_ctx *ctx, size_t outSize);
void blake2b_update(blake2b_ctx *ctx, const void *msg, size_t msgSize);
void blake2b_finish(blake2b_ctx *ctx, void *out);

#endif

void blake2b_nativeIn   (void     *out,    size_t outSize, const uint64_t *in, size_t size);
void blake2b_nativeInOut(uint64_t  out[8],                 const uint64_t *in, size_t size);
