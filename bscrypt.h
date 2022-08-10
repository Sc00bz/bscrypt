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

/**
 * This function is called after the hashing has finish and given a binary hash.
 * You should encrypt at least 128 bits of the original hash and discard any
 * unencrypted hash bytes. It is strongly suggested you encrypt in either single
 * block ECB (and discard the rest of the hash) or NULL-IV-CBC-CTS modes. This
 * function must be deterministic as the encrypted hash is compared directly to
 * another encrypted hash. You could use a keyed hash but it's better to encrypt
 * so you can rotate keys without needing to rehash the password. Thus why I
 * called this "DETERMINISTIC_ENCRYPT_HASH_FUNC", but I can't really stop you.
 * I can just look at you with disapproval.
 *
 * @param void *encryptHashParams     - Your encrypted hash params. Anything needed for your implementation.
 * @param void *hash                  - Hash to encrypt.
 * @param size_t hashSize             - Size of hash.
 * @param size_t maxEncryptedHashSize - Maximum size of the encrypted hash.
 * @return size_t - Size of encrypted hash.
 */
typedef size_t (*DETERMINISTIC_ENCRYPT_HASH_FUNC)(
	void   *encryptHashParams,
	void   *hash,
	size_t  hashSize,
	size_t  maxEncryptedHashSize);

// $bscrypt$m=67108864,t=4294967295,p=4294967295$salt..................hash............................[.........]
const size_t BSCRYPT_HASH_MAX_SIZE           = 112;
const size_t BSCRYPT_ENCRYPTED_HASH_MAX_SIZE = 32;
const uint32_t MEMORY_KIB_MIN = 16;
const uint32_t MEMORY_KIB_MAX = 67108864;
const uint32_t ITERATIONS_MIN = 2;

int bscrypt_kdf(
	void       *output,   size_t outputSize,
	const void *password, size_t passwordSize,
	const void *salt,     size_t saltSize,
	uint32_t    memoryKiB, uint32_t iterations, uint32_t parallelism,
	uint32_t    maxThreads, int wipeSboxes);
int bscrypt_hash(
	char        hash[BSCRYPT_HASH_MAX_SIZE],
	const void *password, size_t passwordSize,
	uint32_t    memoryKiB, uint32_t iterations, uint32_t parallelism,
	uint32_t    maxThreads, int wipeSboxes, DETERMINISTIC_ENCRYPT_HASH_FUNC encryptFunc = NULL, void *encryptHashParams = NULL);
int bscrypt_verify(
	const char *hash,
	const void *password, size_t passwordSize,
	uint32_t    maxThreads, int wipeSboxes, DETERMINISTIC_ENCRYPT_HASH_FUNC encryptFunc = NULL, void *encryptHashParams = NULL);
int bscrypt_needsRehash(
	const char *hash,
	uint32_t    memoryKiB, uint32_t iterations, uint32_t parallelism);
