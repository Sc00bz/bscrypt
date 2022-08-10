/*
	CSPRNG - A CSPRNG and modulo a random number without bias.

	Written in 2016-2018 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#ifdef _WIN32
	#include <windows.h>
#else
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <unistd.h>
#endif
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
#include "csprng.h"

/**
 * Fills buffer with random using a CSPRNG.
 *
 * @param buffer - Buffer to receive the random data.
 * @param size   - Size of buffer.
 * @return Zero on success, otherwise non-zero
 */
int getRandom(void *buffer, size_t size)
{
	if (size > 0)
	{
#ifdef _WIN32
		static HCRYPTPROV hCryptProv = NULL;
		const DWORD       DWORD_MAX  = (((DWORD) 1) << (8 * sizeof(DWORD) - 1)) - 1;

		if (hCryptProv == NULL && !CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		{
			hCryptProv = NULL;
			return 1;
		}

		while (size > 0)
		{
			DWORD curSize = (DWORD) size;

			if ((size_t) curSize != size || curSize < 0)
			{
				curSize = DWORD_MAX;
			}
			if (!CryptGenRandom(hCryptProv, curSize, (BYTE*) buffer))
			{
				return 1;
			}
			size -= (size_t) curSize;
			buffer = ((uint8_t*) buffer) + curSize;
		}
#else
		int fin = open("/dev/urandom", O_RDONLY);

		if (fin == -1)
		{
			return 1;
		}

		while (size > 0)
		{
			ssize_t curSize = (ssize_t) size;

			if (size > (size_t) SSIZE_MAX)
			{
				curSize = SSIZE_MAX;
			}
			if (read(fin, buffer, curSize) != (ssize_t) curSize)
			{
				close(fin);
				return 1;
			}
			size -= (size_t) curSize;
			buffer = ((uint8_t*) buffer) + curSize;
		}
		close(fin);
#endif
	}

	return 0;
}
