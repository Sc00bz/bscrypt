/*
	bscrypt

	Written in 20??-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#pragma once

#include <stdint.h>
#include "architecture.h"

#ifdef _WIN32
	#include <windows.h>
	typedef LARGE_INTEGER TIMER_TYPE;
	#define TIMER_FUNC(t)             QueryPerformanceCounter(&t)

	inline double TIMER_DIFF(LARGE_INTEGER s, LARGE_INTEGER e)
	{
		LARGE_INTEGER f;
		QueryPerformanceFrequency(&f);
		return ((double) (e.QuadPart - s.QuadPart)) / f.QuadPart;
	}
#else
	#include <sys/time.h>

	typedef timeval TIMER_TYPE;
	#define TIMER_FUNC(t)             gettimeofday(&t, NULL)
	#define TIMER_DIFF(s,e)           ((e.tv_sec - s.tv_sec) + (e.tv_usec - s.tv_usec) / (double)1000000.0)
#endif

#define SWAP_ENDIAN_64_(x) \
	( \
		 ((x) << 56) | \
		(((x) << 40) & UINT64_C(0x00ff000000000000)) | \
		(((x) << 24) & UINT64_C(0x0000ff0000000000)) | \
		(((x) <<  8) & UINT64_C(0x000000ff00000000)) | \
		(((x) >>  8) & UINT64_C(0x00000000ff000000)) | \
		(((x) >> 24) & UINT64_C(0x0000000000ff0000)) | \
		(((x) >> 40) & UINT64_C(0x000000000000ff00)) | \
		 ((x) >> 56) \
	)
#define SWAP_ENDIAN_64(x)  SWAP_ENDIAN_64_(((uint64_t) (x)))

enum instructionSets
{
	IS_MMX      = 0x0001,
	IS_SSE      = 0x0002,
	IS_SSE2     = 0x0004,
	IS_SSE3     = 0x0008,
	IS_SSSE3    = 0x0010,
	IS_SSE41    = 0x0020,
	IS_SSE42    = 0x0040,
	IS_SSE4A    = 0x0080,
	IS_AVX      = 0x0100,
	IS_XOP      = 0x0200,
	IS_AVX2     = 0x0400,
	IS_AVX512F  = 0x0800,
	IS_AVX512DQ = 0x1000,
	IS_OS_YMM   = 0x2000,
	IS_OS_ZMM   = 0x4000,
	IS_NEON     = 0x8000,
};

int constTimeCmpEq(const void *a, const void *b, size_t size);
void secureClearMemory(void *mem, size_t size);
uint32_t getInstructionSets(uint32_t mask = 0xffffffff);
