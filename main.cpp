#include <stdio.h>
#include "common.h"
#include "bscrypt.h"

int main()
{
	TIMER_TYPE s, e;
	char hash[BSCRYPT_HASH_MAX_SIZE];

	// Settings to match Pufferfish2
	// m=4, t=13
	// m=5, t=12
	// ...
	// m=12, t=5
	uint32_t t[] = {33065, 16465, 8219, 4109, 2058, 1033, 521, 265, 137};
	for (uint32_t p = 1; p <= 4; p *= 2)
	{
		for (uint32_t i = 0, m = 16; i < 9; i++, m *= 2)
		{
			bscrypt_hash(hash, "password", sizeof("password") - 1, m, (t[i] + p - 1) / p, p, p, 0);

			TIMER_FUNC(s);
			for (int j = 0; j <10; j++)
			{
				bscrypt_verify(hash, "password", sizeof("password") - 1, p, 0);
			}
			TIMER_FUNC(e);

			printf("m=%u, t=%u, p=%u: %f ms\n", m, (t[i] + p - 1) / p, p, TIMER_DIFF(s, e) / 10.0 * 1000);
		}
	}

	// Settings for <10 kH/s/GPU
	for (uint32_t p = 1; p <= 4; p++)
	{
		for (uint32_t m = 16; m <= 256; m += 16)
		{
			uint32_t t = 1900000 / (1024 * m * p) + 1;

			bscrypt_hash(hash, "password", sizeof("password") - 1, m, t, p, p, 0);

			TIMER_FUNC(s);
			for (int j = 0; j <10; j++)
			{
				bscrypt_verify(hash, "password", sizeof("password") - 1, p, 0);
			}
			TIMER_FUNC(e);

			printf("m=%u, t=%u, p=%u: %f ms\n", m, t, p, TIMER_DIFF(s, e) / 10.0 * 1000);
		}
	}

	// Settings to match bcrypt cost 15 (<85 H/s/GPU)
	for (uint32_t p = 1; p <= 4; p++)
	{
		for (uint32_t m = 16; m <= 256; m += 16)
		{
			uint32_t t = 223529412 / (1024 * m * p) + 1;

			bscrypt_hash(hash, "password", sizeof("password") - 1, m, t, p, p, 0);

			TIMER_FUNC(s);
			for (int j = 0; j <10; j++)
			{
				bscrypt_verify(hash, "password", sizeof("password") - 1, p, 0);
			}
			TIMER_FUNC(e);

			printf("m=%u, t=%u, p=%u: %f ms\n", m, t, p, TIMER_DIFF(s, e) / 10.0 * 1000);
		}
	}

	// Settings to match bcrypt cost 9 (5300 H/s/GPU)
	for (uint32_t p = 1; p <= 4; p++)
	{
		uint32_t m = 256;
		uint32_t t = 190000000 / (53 * m * 1024 * p) + 1;

		bscrypt_hash(hash, "password", sizeof("password") - 1, m, t, p, p, 0);

		TIMER_FUNC(s);
		for (int j = 0; j < 10; j++)
		{
			bscrypt_verify(hash, "password", sizeof("password") - 1, p, 0);
		}
		TIMER_FUNC(e);

		printf("m=%u, t=%u, p=%u: %f ms\n", m, t, p, TIMER_DIFF(s, e) / 10.0 * 1000);
	}

	return 0;
}
