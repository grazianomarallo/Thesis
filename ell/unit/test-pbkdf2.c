/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ell/ell.h>

struct pbkdf2_data {
	const char *password;
	const char *salt;
	unsigned int salt_len;
	unsigned int count;
	unsigned int key_len;
	const char *key;
};

static void pbkdf2_test(const void *data)
{
	const struct pbkdf2_data *test = data;
	unsigned int salt_len;
	unsigned int key_len;
	unsigned char output[25];
	char *key;
	bool result;

	salt_len = test->salt_len ? : strlen(test->salt);

	key_len = test->key_len ? : (strlen(test->key) / 2);

	result = l_pkcs5_pbkdf2(L_CHECKSUM_SHA1, test->password,
				(const uint8_t *) test->salt, salt_len,
				test->count, output, key_len);

	assert(result == true);

	key = l_util_hexstring(output, key_len);

	assert(strcmp(test->key, key) == 0);

	l_free(key);
}

static const struct pbkdf2_data pbkdf2_test_vector_1 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 1,
	.key		= "0c60c80f961f0e71f3a9b524af6012062fe037a6",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_2 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 2,
	.key		= "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_3 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 4096,
	.key		= "4b007901b765489abead49d926f721d065a429c1",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_4 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 16777216,
	.key		= "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_5 = {
	.password	= "passwordPASSWORDpassword",
	.salt		= "saltSALTsaltSALTsaltSALTsaltSALTsalt",
	.count		= 4096,
	.key		= "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
	.key_len	= 25,
};

static const struct pbkdf2_data athena_test_vector_1 = {
	.password	= "password",
	.salt		= "ATHENA.MIT.EDUraeburn",
	.count		= 1,
	.key		= "cdedb5281bb2f801565a1122b2563515",
};

static const struct pbkdf2_data athena_test_vector_2 = {
	.password	= "password",
	.salt		= "ATHENA.MIT.EDUraeburn",
	.count		= 2,
	.key		= "01dbee7f4a9e243e988b62c73cda935d",
};

static const struct pbkdf2_data athena_test_vector_3 = {
	.password	= "password",
	.salt		= "ATHENA.MIT.EDUraeburn",
	.count		= 1200,
	.key		= "5c08eb61fdf71e4e4ec3cf6ba1f5512b",
};

static const struct pbkdf2_data athena_test_vector_4 = {
	.password	= "password",
	.salt		= "\x12\x34\x56\x78\x78\x56\x34\x12",
	.count		= 5,
	.key		= "d1daa78615f287e6a1c8b120d7062a49",
};

static const struct pbkdf2_data athena_test_vector_5 = {
	.password	= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
			  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	.salt		= "pass phrase equals block size",
	.count		= 1200,
	.key		= "139c30c0966bc32ba55fdbf212530ac9",
};

static const struct pbkdf2_data athena_test_vector_6 = {
	.password	= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
			  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	.salt		= "pass phrase exceeds block size",
	.count		= 1200,
	.key		= "9ccad6d468770cd51b10e6a68721be61",
};

static const struct pbkdf2_data athena_test_vector_7 = {
	.password	= "\xf0\x9d\x84\x9e",	/* g-clef (0xf09d849e) */
	.salt		= "EXAMPLE.COMpianist",
	.count		= 50,
	.key		= "6b9cf26d45455a43a5b8bb276a403b39",
};

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_checksum_is_supported(L_CHECKSUM_SHA1, true)) {
		printf("SHA1 support missing, skipping...\n");
		goto done;
	}

	l_test_add("/pbkdf2-sha1/PBKDF2 Test vector 1",
					pbkdf2_test, &pbkdf2_test_vector_1);
	l_test_add("/pbkdf2-sha1/PBKDF2 Test vector 2",
					pbkdf2_test, &pbkdf2_test_vector_2);
	l_test_add("/pbkdf2-sha1/PBKDF2 Test vector 3",
					pbkdf2_test, &pbkdf2_test_vector_3);
	l_test_add("/pbkdf2-sha1/PBKDF2 Test vector 4",
					pbkdf2_test, &pbkdf2_test_vector_4);
	l_test_add("/pbkdf2-sha1/PBKDF2 Test vector 5",
					pbkdf2_test, &pbkdf2_test_vector_5);

	l_test_add("/pbkdf2-sha1/ATHENA Test vector 1",
					pbkdf2_test, &athena_test_vector_1);
	l_test_add("/pbkdf2-sha1/ATHENA Test vector 2",
					pbkdf2_test, &athena_test_vector_2);
	l_test_add("/pbkdf2-sha1/ATHENA Test vector 3",
					pbkdf2_test, &athena_test_vector_3);
	l_test_add("/pbkdf2-sha1/ATHENA Test vector 4",
					pbkdf2_test, &athena_test_vector_4);
	l_test_add("/pbkdf2-sha1/ATHENA Test vector 5",
					pbkdf2_test, &athena_test_vector_5);
	l_test_add("/pbkdf2-sha1/ATHENA Test vector 6",
					pbkdf2_test, &athena_test_vector_6);
	l_test_add("/pbkdf2-sha1/ATHENA Test vector 7",
					pbkdf2_test, &athena_test_vector_7);

done:
	return l_test_run();
}
