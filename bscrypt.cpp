/*
	bscrypt

	Written in 2019-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "bscrypt.h"
#include "base64.h"
#include "blake2b.h"
#include "notblake2b.h"
#include "common.h"
#include "csprng.h"
#include "threads.h"

#define ROTR64(n, s) (((n) >> (s)) | ((n) << (64 - (s))))

static inline void bscrypt_work_fill(uint64_t *sbox, const uint64_t seed[8], size_t count, uint32_t threadId)
{
	// sbox[0..8]  = H(seed || threadId)
	// sbox[8..16] = H(sbox[0..8])
	for (size_t i = 0; i < 8; i++)
	{
		sbox[i] = seed[i];
	}
	sbox[8] = threadId;
	blake2b_nativeInOut(sbox, sbox, 8 * sizeof(uint64_t) + sizeof(uint32_t));
	blake2b_nativeInOut(sbox + 8, sbox, 8 * sizeof(uint64_t));

	// Main fill
	for (uint64_t *end = sbox + count - 16; sbox < end; sbox += 16)
	{
		for (int i = 0; i < 16; i++)
		{
			sbox[i + 16] = sbox[i];
		}
		notBlake2b_block(sbox + 16);
	}
}

static inline void bscrypt_work_finish(uint64_t work[8], uint64_t iv, uint64_t *sbox, size_t count)
{
	for (int i = 0; i < 16; i++)
	{
		sbox[i] = (sbox[i] + iv) ^ sbox[i + 16];
	}
	for (size_t i = 32; i < count; i += 32)
	{
		sbox[ 0] = (sbox[ 0] + sbox[i +  0]) ^ sbox[i + 16];
		sbox[ 1] = (sbox[ 1] + sbox[i +  1]) ^ sbox[i + 17];
		sbox[ 2] = (sbox[ 2] + sbox[i +  2]) ^ sbox[i + 18];
		sbox[ 3] = (sbox[ 3] + sbox[i +  3]) ^ sbox[i + 19];
		sbox[ 4] = (sbox[ 4] + sbox[i +  4]) ^ sbox[i + 20];
		sbox[ 5] = (sbox[ 5] + sbox[i +  5]) ^ sbox[i + 21];
		sbox[ 6] = (sbox[ 6] + sbox[i +  6]) ^ sbox[i + 22];
		sbox[ 7] = (sbox[ 7] + sbox[i +  7]) ^ sbox[i + 23];
		sbox[ 8] = (sbox[ 8] + sbox[i +  8]) ^ sbox[i + 24];
		sbox[ 9] = (sbox[ 9] + sbox[i +  9]) ^ sbox[i + 25];
		sbox[10] = (sbox[10] + sbox[i + 10]) ^ sbox[i + 26];
		sbox[11] = (sbox[11] + sbox[i + 11]) ^ sbox[i + 27];
		sbox[12] = (sbox[12] + sbox[i + 12]) ^ sbox[i + 28];
		sbox[13] = (sbox[13] + sbox[i + 13]) ^ sbox[i + 29];
		sbox[14] = (sbox[14] + sbox[i + 14]) ^ sbox[i + 30];
		sbox[15] = (sbox[15] + sbox[i + 15]) ^ sbox[i + 31];
	}
	blake2b_nativeInOut(work, sbox, 16 * sizeof(uint64_t));
}

static void bscrypt_work_32_4x(uint64_t work[8], const uint64_t seed[8], uint64_t *sbox, size_t sboxOffset, size_t count, size_t mask, uint32_t iterations, uint32_t threadId)
{
	// Init sboxes
	uint64_t *s0 = sbox;
	uint64_t *s1 = s0 + sboxOffset;
	bscrypt_work_fill(sbox, seed, count, threadId);

	// Init state
	// state = blake2b(s[count-8..count] || H(seed || threadId))
	for (size_t i = 0; i < 8; i++)
	{
		sbox[count + i] = sbox[i];
	}
	blake2b_nativeInOut(sbox + count, sbox + count - 8, 16 * sizeof(uint64_t));
	uint64_t a = sbox[count    ];
	uint64_t b = sbox[count + 1];
	uint64_t c = sbox[count + 2];
	uint64_t d = sbox[count + 3];
	uint64_t e = sbox[count + 4];
	uint64_t f = sbox[count + 5];
	uint64_t g = sbox[count + 6];
	uint64_t h = sbox[count + 7];

	// Main loop
	for (uint32_t i = 0; i < iterations; i++)
	{
		for (size_t j = 0; j < count; j += 8)
		{
			a ^= sbox[j    ];
			b ^= sbox[j + 1];
			c ^= sbox[j + 2];
			d ^= sbox[j + 3];
			e ^= sbox[j + 4];
			f ^= sbox[j + 5];
			g ^= sbox[j + 6];
			h ^= sbox[j + 7];

			a += s0[(e >> 32) & mask]; a ^= s1[e & mask];
			b += s0[(f >> 32) & mask]; b ^= s1[f & mask];
			c += s0[(g >> 32) & mask]; c ^= s1[g & mask];
			d += s0[(h >> 32) & mask]; d ^= s1[h & mask];
			e += s0[(a >> 32) & mask]; e ^= s1[a & mask];
			f += s0[(b >> 32) & mask]; f ^= s1[b & mask];
			g += s0[(c >> 32) & mask]; g ^= s1[c & mask];
			h += s0[(d >> 32) & mask]; h ^= s1[d & mask];

			a += s0[(f >> 32) & mask]; a ^= s1[f & mask];
			b += s0[(g >> 32) & mask]; b ^= s1[g & mask];
			c += s0[(h >> 32) & mask]; c ^= s1[h & mask];
			d += s0[(e >> 32) & mask]; d ^= s1[e & mask];
			f += s0[(a >> 32) & mask]; f ^= s1[a & mask];
			g += s0[(b >> 32) & mask]; g ^= s1[b & mask];
			h += s0[(c >> 32) & mask]; h ^= s1[c & mask];
			e += s0[(d >> 32) & mask]; e ^= s1[d & mask];

			a += s0[(g >> 32) & mask]; a ^= s1[g & mask];
			b += s0[(h >> 32) & mask]; b ^= s1[h & mask];
			c += s0[(e >> 32) & mask]; c ^= s1[e & mask];
			d += s0[(f >> 32) & mask]; d ^= s1[f & mask];
			g += s0[(a >> 32) & mask]; g ^= s1[a & mask];
			h += s0[(b >> 32) & mask]; h ^= s1[b & mask];
			e += s0[(c >> 32) & mask]; e ^= s1[c & mask];
			f += s0[(d >> 32) & mask]; f ^= s1[d & mask];

			a += s0[(h >> 32) & mask]; a ^= s1[h & mask];
			b += s0[(e >> 32) & mask]; b ^= s1[e & mask];
			c += s0[(f >> 32) & mask]; c ^= s1[f & mask];
			d += s0[(g >> 32) & mask]; d ^= s1[g & mask];
			h += s0[(a >> 32) & mask]; h ^= s1[a & mask];
			e += s0[(b >> 32) & mask]; e ^= s1[b & mask];
			f += s0[(c >> 32) & mask]; f ^= s1[c & mask];
			g += s0[(d >> 32) & mask]; g ^= s1[d & mask];

			sbox[j    ] += f;
			sbox[j + 1] += g;
			sbox[j + 2] += h;
			sbox[j + 3] += e;
			sbox[j + 4] += b;
			sbox[j + 5] += c;
			sbox[j + 6] += d;
			sbox[j + 7] += a;

			a = ROTR64(a, 15);
			b = ROTR64(b, 35);
			c = ROTR64(c, 17);
			d = ROTR64(d, 41);

			j += 8;
			a += sbox[j    ];
			b += sbox[j + 1];
			c += sbox[j + 2];
			d += sbox[j + 3];
			e += sbox[j + 4];
			f += sbox[j + 5];
			g += sbox[j + 6];
			h += sbox[j + 7];

			a ^= s0[(e >> 32) & mask]; a += s1[e & mask];
			b ^= s0[(f >> 32) & mask]; b += s1[f & mask];
			c ^= s0[(g >> 32) & mask]; c += s1[g & mask];
			d ^= s0[(h >> 32) & mask]; d += s1[h & mask];
			e ^= s0[(a >> 32) & mask]; e += s1[a & mask];
			f ^= s0[(b >> 32) & mask]; f += s1[b & mask];
			g ^= s0[(c >> 32) & mask]; g += s1[c & mask];
			h ^= s0[(d >> 32) & mask]; h += s1[d & mask];

			a ^= s0[(f >> 32) & mask]; a += s1[f & mask];
			b ^= s0[(g >> 32) & mask]; b += s1[g & mask];
			c ^= s0[(h >> 32) & mask]; c += s1[h & mask];
			d ^= s0[(e >> 32) & mask]; d += s1[e & mask];
			f ^= s0[(a >> 32) & mask]; f += s1[a & mask];
			g ^= s0[(b >> 32) & mask]; g += s1[b & mask];
			h ^= s0[(c >> 32) & mask]; h += s1[c & mask];
			e ^= s0[(d >> 32) & mask]; e += s1[d & mask];

			a ^= s0[(g >> 32) & mask]; a += s1[g & mask];
			b ^= s0[(h >> 32) & mask]; b += s1[h & mask];
			c ^= s0[(e >> 32) & mask]; c += s1[e & mask];
			d ^= s0[(f >> 32) & mask]; d += s1[f & mask];
			g ^= s0[(a >> 32) & mask]; g += s1[a & mask];
			h ^= s0[(b >> 32) & mask]; h += s1[b & mask];
			e ^= s0[(c >> 32) & mask]; e += s1[c & mask];
			f ^= s0[(d >> 32) & mask]; f += s1[d & mask];

			a ^= s0[(h >> 32) & mask]; a += s1[h & mask];
			b ^= s0[(e >> 32) & mask]; b += s1[e & mask];
			c ^= s0[(f >> 32) & mask]; c += s1[f & mask];
			d ^= s0[(g >> 32) & mask]; d += s1[g & mask];
			h ^= s0[(a >> 32) & mask]; h += s1[a & mask];
			e ^= s0[(b >> 32) & mask]; e += s1[b & mask];
			f ^= s0[(c >> 32) & mask]; f += s1[c & mask];
			g ^= s0[(d >> 32) & mask]; g += s1[d & mask];

			sbox[j    ] ^= f;
			sbox[j + 1] ^= g;
			sbox[j + 2] ^= h;
			sbox[j + 3] ^= e;
			sbox[j + 4] ^= b;
			sbox[j + 5] ^= c;
			sbox[j + 6] ^= d;
			sbox[j + 7] ^= a;

			e = ROTR64(e, 21);
			f = ROTR64(f, 45);
			g = ROTR64(g, 27);
			h = ROTR64(h, 47);
		}
	}

	// Finish
	bscrypt_work_finish(work, ((((((h ^ g) + f) ^ e) + d) ^ c) + b) ^ a, sbox, count);
}

struct bscrypt_threadArgs
{
	PMUTEX          pmutex;
	uint32_t       *threadId;
	uint64_t       *work;
	const uint64_t *seed;
	uint64_t       *sbox;
	size_t          sboxOffset;
	size_t          count;
	size_t          mask;
	uint32_t        iterations;
	uint32_t        parallelism;
	int             wipeSboxes;
};

static void *bscrypt_thread(void *args)
{
	uint64_t        threadWork[8];
	PMUTEX          pmutex      = ((bscrypt_threadArgs*) args)->pmutex;
	uint32_t       *threadId    = ((bscrypt_threadArgs*) args)->threadId;
	uint64_t       *work        = ((bscrypt_threadArgs*) args)->work;
	const uint64_t *seed        = ((bscrypt_threadArgs*) args)->seed;
	uint64_t       *sbox        = ((bscrypt_threadArgs*) args)->sbox;
	size_t          sboxOffset  = ((bscrypt_threadArgs*) args)->sboxOffset;
	size_t          count       = ((bscrypt_threadArgs*) args)->count;
	size_t          mask        = ((bscrypt_threadArgs*) args)->mask;
	uint32_t        iterations  = ((bscrypt_threadArgs*) args)->iterations;
	uint32_t        parallelism = ((bscrypt_threadArgs*) args)->parallelism;
	uint32_t        currentThreadId;

	while (1)
	{
		// Next work
		PMUTEX_LOCK(pmutex);
		currentThreadId = *threadId;
		(*threadId)++;
		PMUTEX_UNLOCK(pmutex);
		if (currentThreadId >= parallelism)
		{
			break;
		}

		// Do work
		bscrypt_work_32_4x(threadWork, seed, sbox, sboxOffset, count, mask, iterations, currentThreadId);

		// Combine work
		PMUTEX_LOCK(pmutex);
		for (uint32_t i = 0; i < 8; i++)
		{
			work[i] ^= threadWork[i];
		}
		PMUTEX_UNLOCK(pmutex);
	}

	// Clear
	secureClearMemory(threadWork, sizeof(threadWork));
	if (((bscrypt_threadArgs*) args)->wipeSboxes)
	{
		secureClearMemory(sbox, sizeof(uint64_t) * (count + 8));
	}

	return NULL;
}

static size_t readUint32(uint32_t &out, const char *str, size_t offset, char endingChar)
{
	size_t   i = 0;
	uint64_t ret = 0;
	char     ch;

	str += offset;
	if (str[0] == '0' && str[1] != endingChar)
	{
		return SIZE_MAX;
	}
	for (; i < 11; i++)
	{
		ch = str[i];
		if (ch < '0' || ch > '9')
		{
			break;
		}
		ret *= 10;
		ret += (uint64_t) (ch - '0');
	}
	if (ch != endingChar || ret > UINT32_MAX)
	{
		return SIZE_MAX;
	}
	out = (uint32_t) ret;
	return offset + i + 1;
}

static size_t writeUint32(char *str, uint32_t num)
{
	size_t i = 0;

	if (num == 0)
	{
		i = 1;
		str[0] = '0';
	}
	else
	{
		for (; num != 0; i++)
		{
			str[i] = ((char) (num % 10)) + '0';
			num /= 10;
		}
		// Revese
		for (size_t j = 0, k = i - 1; j < k; j++, k--)
		{
			char ch = str[j];
			str[j] = str[k];
			str[k] = ch;
		}
	}
	return i;
}

static size_t bscrypt_decodeHash(const char hash[BSCRYPT_HASH_MAX_SIZE], uint32_t &memoryKiB, uint32_t &iterations, uint32_t &parallelism)
{
	size_t offset;

	if (memcmp(hash, "$bscrypt$m=", 11) != 0)
	{
		return SIZE_MAX;
	}
	offset = readUint32(memoryKiB, hash, 11, ',');
	if (offset == SIZE_MAX || memcmp(hash + offset, "t=", 2) != 0)
	{
		return SIZE_MAX;
	}
	offset = readUint32(iterations, hash, offset + 2, ',');
	if (offset == SIZE_MAX || memcmp(hash + offset, "p=", 2) != 0)
	{
		return SIZE_MAX;
	}
	offset = readUint32(parallelism, hash, offset + 2, '$');
	if (offset == SIZE_MAX)
	{
		return SIZE_MAX;
	}
	return offset;
}

/**
 * Generates a key with bscrypt.
 *
 * @param void       *output       - Output of bscrypt.
 * @param size_t      outputSize   - Output size.
 * @param const void *password     - The password.
 * @param size_t      passwordSize - Size of the password.
 * @param const void *salt         - The salt.
 * @param size_t      saltSize     - Size of the salt.
 * @param uint32_t    memoryKiB    - The size of the sboxes in KiB (m).
 * @param uint32_t    iterations   - The number of iterations (t).
 * @param uint32_t    parallelism  - The amount of parallelism (p).
 * @param uint32_t    maxThreads   - The maximum number of threads.
 * @param int         wipeSboxes   - Whether to wipe the sboxes afterward.
 * @return On success 0, otherwise non-zero.
 */
int bscrypt_kdf(void *output, size_t outputSize, const void *password, size_t passwordSize, const void *salt, size_t saltSize, uint32_t memoryKiB, uint32_t iterations, uint32_t parallelism, uint32_t maxThreads, int wipeSboxes)
{
	size_t sboxOffset;
	size_t count;
	size_t mask;

	// Limits
	if      (memoryKiB   > MEMORY_KIB_MAX)           { memoryKiB = MEMORY_KIB_MAX; }
	else if (memoryKiB   < MEMORY_KIB_MIN)           { memoryKiB = MEMORY_KIB_MIN; }
	if      (memoryKiB   > SIZE_MAX / (size_t) 1024) { return 1; }
	if      (iterations  < ITERATIONS_MIN)           { iterations = ITERATIONS_MIN; }
	if      (parallelism < 1)                        { parallelism = 1; }
	if      (maxThreads  > parallelism)              { maxThreads = parallelism; }

	count = (size_t) 1024 / sizeof(uint64_t) * memoryKiB;

	// Set sbox info
	if (memoryKiB == MEMORY_KIB_MAX)
	{
		// Special case for max size (64 GiB):
		// 2 separate sboxes of 32 GiB each vs normal case of 1 sbox of 64 GiB
		// because the mask for a 64 GiB sbox is larger than a 32 bit int
		sboxOffset = count / 2;
		mask = sboxOffset - 1;
	}
	else
	{
		// sboxSize = 1 << floor(log2(1024 / sizeof(uint64_t) * memoryKiB));
		size_t   sboxSize = 1 << 7; // 7 = log2(1024 / 8)
		uint32_t shift    = 16;
		while (shift)
		{
			if (memoryKiB >> shift)
			{
				sboxSize  <<= shift;
				memoryKiB >>= shift;
			}
			shift /= 2;
		}

		sboxOffset = count - sboxSize;
		mask = sboxSize - 1;
	}

	union
	{
		uint64_t workSeed[16];
		struct
		{
			uint64_t work[8];
			uint64_t seed[8];
		};
	};
	memset(work, 0, sizeof(work));

	// Step 1: seed = H(inputs)
	// seed = H(H(salt) || password)
	blake2b_ctx ctx;
	blake2b_init(&ctx, sizeof(seed));
	blake2b_update(&ctx, salt, saltSize);
	blake2b_finish(&ctx, seed);
	blake2b_update(&ctx, seed, sizeof(seed));
	blake2b_update(&ctx, password, passwordSize);
	blake2b_finish(&ctx, seed);

	// Step 2: work = doWork(seed)
	if (maxThreads == 1)
	{
		uint64_t threadWork[8];
		uint64_t *sbox = new uint64_t[count + 8 + 64 / sizeof(uint64_t)];
		// Align to 64 bytes
		uint64_t *sboxAligned = (uint64_t*) ((((uintptr_t) sbox) + 63) & ~((uintptr_t) 63));
		
		for (uint32_t i = 0; i < parallelism; i++)
		{
			bscrypt_work_32_4x(threadWork, seed, sboxAligned, sboxOffset, count, mask, iterations, i);

			for (uint32_t j = 0; j < 8; j++)
			{
				work[j] ^= threadWork[j];
			}
		}

		// Clean up
		secureClearMemory(threadWork, sizeof(threadWork));
		if (wipeSboxes)
		{
			secureClearMemory(sboxAligned, sizeof(uint64_t) * (count + 8));
		}
		delete [] sbox;
	}
	else
	{
		THREAD              *threads       = new THREAD[maxThreads];
		bscrypt_threadArgs  *args          = new bscrypt_threadArgs[maxThreads];
		uint64_t           **sboxes        = new uint64_t*[maxThreads];
		uint64_t           **sboxesAligned = new uint64_t*[maxThreads];
		PMUTEX               pmutex;
		uint32_t             threadId = 0;

		// Init
		PMUTEX_CREATE(pmutex);
		for (uint32_t i = 0; i < maxThreads; i++)
		{
			sboxes[i] = new uint64_t[count + 8 + 64 / sizeof(uint64_t)];

			args[i].pmutex      = pmutex;
			args[i].threadId    = &threadId;
			args[i].work        = work;
			args[i].seed        = seed;
			// Align to 64 bytes
			args[i].sbox        = (uint64_t*) ((((uintptr_t) sboxes[i]) + 63) & ~((uintptr_t) 63));
			args[i].sboxOffset  = sboxOffset;
			args[i].count       = count;
			args[i].mask        = mask;
			args[i].iterations  = iterations;
			args[i].parallelism = parallelism;
			args[i].wipeSboxes  = wipeSboxes;
		}

		// Run threads
		for (uint32_t i = 0; i < maxThreads; i++)
		{
			if (THREAD_CREATE(threads[i], bscrypt_thread, args + i))
			{
				if (i > 0)
				{
					// At least a thread was created just let them run and exit
					for (uint32_t j = 0; j < i; j++)
					{
						THREAD_WAIT(threads[j]);
					}
					for (uint32_t i = 0; i < maxThreads; i++)
					{
						delete [] sboxes[i];
					}
					maxThreads = 0;
				}
				else
				{
					// Can't create a thread, clean up and go single threaded

					// Clean up
					PMUTEX_DELETE(pmutex);
					for (uint32_t i = 0; i < maxThreads; i++)
					{
						delete [] sboxes[i];
					}
					delete [] threads;
					delete [] args;
					delete [] sboxes;
					delete [] sboxesAligned;

					return bscrypt_kdf(output, outputSize, password, passwordSize, salt, saltSize, memoryKiB, iterations, parallelism, 1, wipeSboxes);
				}
			}
		}
		for (uint32_t i = 0; i < maxThreads; i++)
		{
			THREAD_WAIT(threads[i]);
		}

		// Clean up
		PMUTEX_DELETE(pmutex);
		for (uint32_t i = 0; i < maxThreads; i++)
		{
			delete [] sboxes[i];
		}
		delete [] threads;
		delete [] args;
		delete [] sboxes;
		delete [] sboxesAligned;
	}

	// Step 3: output = kdf(work, seed)
	uint64_t i = 1;
	while (outputSize > 64)
	{
		blake2b_nativeIn(output, 64, workSeed, 16 * sizeof(uint64_t));
		output = ((uint8_t*) output) + 64;
		outputSize -= 64;
		workSeed[0] ^= i;
		i++;
	}
	if (outputSize != 0)
	{
		blake2b_nativeIn(output, outputSize, workSeed, 16 * sizeof(uint64_t));
	}

	// Clear
	secureClearMemory(workSeed, sizeof(workSeed));

	return 0;
}

static int bscrypt_hash_(char hash[BSCRYPT_HASH_MAX_SIZE], const void *password, size_t passwordSize, const uint8_t salt[16], uint32_t memoryKiB, uint32_t iterations, uint32_t parallelism, uint32_t maxThreads, int wipeSboxes, DETERMINISTIC_ENCRYPT_HASH_FUNC encryptFunc, void *encryptHashParams)
{
	uint8_t hashBytes[BSCRYPT_ENCRYPTED_HASH_MAX_SIZE];
	size_t hashBytesSize = 24;

	// Limits
	if (memoryKiB > MEMORY_KIB_MAX)
	{
		memoryKiB = MEMORY_KIB_MAX;
	}
	else if (memoryKiB < MEMORY_KIB_MIN)
	{
		memoryKiB = MEMORY_KIB_MIN;
	}
	if (iterations < ITERATIONS_MIN)
	{
		iterations = ITERATIONS_MIN;
	}
	if (parallelism < 1)
	{
		parallelism = 1;
	}

	// Generate hash
	if (bscrypt_kdf(hashBytes, hashBytesSize, password, passwordSize, salt, 16 * sizeof(uint8_t), memoryKiB, iterations, parallelism, maxThreads, wipeSboxes))
	{
		hash[0] = 0;
		return 1;
	}

	// Encrypt
	if (encryptFunc != NULL)
	{
		hashBytesSize = encryptFunc(encryptHashParams, hashBytes, hashBytesSize, BSCRYPT_ENCRYPTED_HASH_MAX_SIZE);
		if (hashBytesSize > BSCRYPT_ENCRYPTED_HASH_MAX_SIZE)
		{
			return 1;
		}
	}

	// Encode
	// $bscrypt$m=#,t=#,p=#$salt..................hash............................
	size_t offset = 11;
	memcpy(hash, "$bscrypt$m=", 11);
	offset += writeUint32(hash + offset, memoryKiB);
	memcpy(hash + offset, ",t=", 3);
	offset += 3;
	offset += writeUint32(hash + offset, iterations);
	memcpy(hash + offset, ",p=", 3);
	offset += 3;
	offset += writeUint32(hash + offset, parallelism);
	hash[offset++] = '$';
	offset += base64Encode(hash + offset, salt, 16 * sizeof(uint8_t), BASE64_ENCODE_FLAG_NO_PAD);
	offset += base64Encode(hash + offset, hashBytes, hashBytesSize, BASE64_ENCODE_FLAG_NO_PAD);
	hash[offset] = 0;

	// Clear
	secureClearMemory(hashBytes, sizeof(hashBytes));

	return 0;
}

/**
 * Generates a bscrypt hash.
 *
 * @param char        hash[BSCRYPT_HASH_MAX_SIZE] - The hash.
 * @param const void *password     - The password.
 * @param size_t      passwordSize - Size of the password.
 * @param uint32_t    memoryKiB    - The size of the sboxes in KiB (m).
 * @param uint32_t    iterations   - The number of iterations (t).
 * @param uint32_t    parallelism  - The amount of parallelism (p).
 * @param uint32_t    maxThreads   - The maximum number of threads.
 * @param int         wipeSboxes   - Whether to wipe the sboxes afterward.
 * @param DETERMINISTIC_ENCRYPT_HASH_FUNC  encryptFunc       - A callback function to encrypt the hash.
 * @param void                            *encryptHashParams - Parameters to pass to the encryption function.
 * @return On success, 0. Otherwise, non-zero.
 */
int bscrypt_hash(char hash[BSCRYPT_HASH_MAX_SIZE], const void *password, size_t passwordSize, uint32_t memoryKiB, uint32_t iterations, uint32_t parallelism, uint32_t maxThreads, int wipeSboxes, DETERMINISTIC_ENCRYPT_HASH_FUNC encryptFunc, void *encryptHashParams)
{
	uint8_t salt[16];

	// Generate salt
	if (getRandom(salt, sizeof(salt)))
	{
		hash[0] = 0;
		return 1;
	}

	// Hash
	int ret = bscrypt_hash_(hash, password, passwordSize, salt, memoryKiB, iterations, parallelism, maxThreads, wipeSboxes, encryptFunc, encryptHashParams);

	// Clear
	secureClearMemory(salt, sizeof(salt));

	return ret;
}

/**
 * Verifies a password against a bscrypt hash.
 *
 * @param const char *hash         - The hash.
 * @param const void *password     - The password.
 * @param size_t      passwordSize - Size of the password.
 * @param uint32_t    maxThreads   - The maximum number of threads.
 * @param int         wipeSboxes   - Whether to wipe the sboxes afterward.
 * @param DETERMINISTIC_ENCRYPT_HASH_FUNC  encryptFunc       - A callback function to encrypt the hash.
 * @param void                            *encryptHashParams - Parameters to pass to the encryption function.
 * @return On correct password, non-zero. Otherwise, 0.
 */
int bscrypt_verify(const char *hash, const void *password, size_t passwordSize, uint32_t maxThreads, int wipeSboxes, DETERMINISTIC_ENCRYPT_HASH_FUNC encryptFunc, void *encryptHashParams)
{
	size_t   offset;
	uint32_t memoryKiB;
	uint32_t iterations;
	uint32_t parallelism;
	uint8_t  salt[16];
	char     hashTest[BSCRYPT_HASH_MAX_SIZE];

	// Decode
	offset = bscrypt_decodeHash(hash, memoryKiB, iterations, parallelism);
	if (offset == SIZE_MAX)
	{
		return 0;
	}
	if (base64Decode(salt, hash + offset, 22, BASE64_DECODE_FLAG_IGNORE_NO_PAD))
	{
		return 0;
	}

	// Hash
	if (bscrypt_hash_(hashTest, password, passwordSize, salt, memoryKiB, iterations, parallelism, maxThreads, wipeSboxes, encryptFunc, encryptHashParams))
	{
		return 0;
	}

	// Compare
	// constTimeCmpEq() to avoid dumb bug reports
	int ret = constTimeCmpEq(hashTest, hash, offset + 55);

	// Clear
	secureClearMemory(hashTest, sizeof(hashTest));

	return ret;
}

/**
 * Checks if the hash needs to be upgraded.
 *
 * @param const char *hash        - The hash.
 * @param uint32_t    memoryKiB   - The size of the sboxes in KiB (m).
 * @param uint32_t    iterations  - The number of iterations (t).
 * @param uint32_t    parallelism - The amount of parallelism (p).
 * @return If upgrade needed, non-zero. Otherwise, 0.
 */
int bscrypt_needsRehash(const char *hash, uint32_t memoryKiB, uint32_t iterations, uint32_t parallelism)
{
	uint32_t hashMemoryKiB;
	uint32_t hashIterations;
	uint32_t hashParallelism;

	if (bscrypt_decodeHash(hash, hashMemoryKiB, hashIterations, hashParallelism) == SIZE_MAX ||
		hashMemoryKiB   != memoryKiB  ||
		hashIterations  != iterations ||
		hashParallelism != parallelism)
	{
		return 1;
	}

	return 0;
}
