/*
	Constant time encoding

	Written in 2014-2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

#pragma once

const int BASE64_FLAG_NONE                  = 0;
const int BASE64_ENCODE_FLAG_NO_PAD         = 1;
const int BASE64_DECODE_FLAG_IGNORE_NO_PAD  = 1;
const int BASE64_DECODE_FLAG_IGNORE_BAD_PAD = 2;

size_t base64DecodedSize(       const char *src, size_t srcSize, int flags = BASE64_DECODE_FLAG_IGNORE_NO_PAD);
size_t base64Encode(char *dest, const void *src, size_t srcSize, int flags = BASE64_ENCODE_FLAG_NO_PAD);
int    base64Decode(void *dest, const char *src, size_t srcSize, int flags = BASE64_DECODE_FLAG_IGNORE_NO_PAD);
