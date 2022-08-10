/*
	bscrypt

	Written in 20??-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#define __STDC_WANT_LIB_EXT1__ 1

#include "common.h"
#ifdef _MSC_VER
	#include <intrin.h>
#endif
#ifdef _WIN32
	#include <windows.h>
#else
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <unistd.h>
#endif
#include <string.h>

/**
 * Constant time compare equal.
 *
 * @param a - Pointer to data.
 * @param b - Pointer to data.
 * @param size - The amount of data to compare.
 * @return Non-zero if equal, otherwise 0.
 */
int constTimeCmpEq(const void *a, const void *b, size_t size)
{
	int ret = 0;

	for (size_t i = 0; i < size; i++)
	{
		ret |= ((const uint8_t*) a)[i] ^ ((const uint8_t*) b)[i];
	}
	return ((-ret) >> 8) + 1;
}

/**
 * Clears memory.
 *
 * @param mem  - Pointer to data to clear.
 * @param size - Size of data.
 */
void secureClearMemory(void *mem, size_t size)
{
	if (size > 0)
	{
#ifdef __STDC_LIB_EXT1__
		memset_s(mem, size, 0, size);
#elif defined(_WIN32)
		SecureZeroMemory(mem, size);
#else
		volatile uint8_t *p = (volatile uint8_t*) mem;
		do
		{
			*p = 0;
			p++;
		} while (--size);
#endif
	}
}

/**
 * Gets instruction sets supported by the CPU.
 *
 * @param mask - Mask off instruction sets for later calls.
 * @return A uint32_t of flags from enum instructionSets (IS_*).
 */
uint32_t getInstructionSets(uint32_t mask)
{
#ifdef ARC_x86
	static uint32_t ret = 0xffffffff;

	if (ret == 0xffffffff)
	{
		uint32_t ecx_1;
		uint32_t edx_1;
		uint32_t ebx_7;
		uint32_t ecx_0x80000001;
		uint32_t edx_0x80000001;

#ifdef _MSC_VER
		int cpuInfo[4];

		__cpuid(cpuInfo, 1);
		ecx_1 = (uint32_t) (cpuInfo[2]);
		edx_1 = (uint32_t) (cpuInfo[3]);
		__cpuid(cpuInfo, 7);
		ebx_7 = (uint32_t) (cpuInfo[1]);
		__cpuid(cpuInfo, 0x80000001);
		ecx_0x80000001 = (uint32_t) (cpuInfo[2]);
		edx_0x80000001 = (uint32_t) (cpuInfo[3]);
#else
		asm(
			"movl   $1,%%eax\n\t"
			"xor    %%ecx,%%ecx\n\t"
			"cpuid\n\t"
			"movl   %%ecx,%0\n\t"
			"movl   %%edx,%1\n\t"
			"movl   $7,%%eax\n\t"
			"xor    %%ecx,%%ecx\n\t"
			"cpuid\n\t"
			"movl   %%ebx,%2\n\t"
			"movl   $2147483649,%%eax\n\t"
			"xor    %%ecx,%%ecx\n\t"
			"cpuid"
			: "=m"(ecx_1), "=m"(edx_1), "=m"(ebx_7), "=c"(ecx_0x80000001), "=d"(edx_0x80000001) // output
			: // input
			: "eax", "ebx"); // used
#endif
		ret = 0;
		if (edx_1          & (1 << 23)) { ret |= IS_MMX;      }
		if (edx_1          & (1 << 25)) { ret |= IS_SSE;      }
		if (edx_1          & (1 << 26)) { ret |= IS_SSE2;     }
		if (ecx_1          & (1 <<  0)) { ret |= IS_SSE3;     }
		if (ecx_1          & (1 <<  9)) { ret |= IS_SSSE3;    }
		if (ecx_1          & (1 << 19)) { ret |= IS_SSE41;    }
		if (ecx_1          & (1 << 20)) { ret |= IS_SSE42;    }
		if (ecx_0x80000001 & (1 <<  6)) { ret |= IS_SSE4A;    }
		if (ecx_1          & (1 << 28)) { ret |= IS_AVX;      }
		if (ecx_0x80000001 & (1 << 11)) { ret |= IS_XOP;      }
		if (ebx_7          & (1 <<  5)) { ret |= IS_AVX2;     }
		if (ebx_7          & (1 << 16)) { ret |= IS_AVX512F;  }
		if (ebx_7          & (1 << 17)) { ret |= IS_AVX512DQ; }

		// OSXSAVE (XGETBV)
		if ((ret & IS_AVX) && (ecx_1 & (1 << 27)))
		{
#ifdef _MSC_VER
			unsigned long long xcr = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
#else
			uint32_t xcr;
			asm(
				"xor   %%ecx,%%ecx\n\t"
				"xgetbv"
				: "=a"(xcr) // output
				: // input
				: "ecx", "edx"); // used
#endif
			if ((xcr & 0x06) == 0x06) { ret |= IS_OS_YMM; }
			if ((xcr & 0xe6) == 0xe6) { ret |= IS_OS_ZMM; }
		}
	}
	ret &= mask;
	return ret;
#elif defined(ARC_ARM)
	// TODO: detect IS_NEON
	return 0;
#else
	return 0;
#endif
}
