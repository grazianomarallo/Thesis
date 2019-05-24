/*
 *      !!!!! KRACK Test Gtk function !!!!!
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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
#include <linux/if_ether.h>
#include <ell/ell.h>
#include <fcntl.h> //include for the open function
#include <regex.h>

#include "src/util.h"
#include "src/eapol.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/handshake.h"

/* Our nonce to use + its size */
static const uint8_t *snonce;

/* Whether step2 was called with the right info */
static bool verify_step2_called;
/* PTK Handshake 2-of-4 frame we are expected to generate + its size */
static const uint8_t *expected_step2_frame;
static size_t expected_step2_frame_size;

/* Whether step4 was called with the right info */
static bool verify_step4_called;
/* Whether install_tk was called with the right info */
static bool verify_install_tk_called;
static bool verify_install_gtk_called;
/* PTK Handshake 4-of-4 frame we are expected to generate + its size */
static const uint8_t *expected_step4_frame;
static size_t expected_step4_frame_size;

/* Whether GTK step2 was called with the right info */
static bool verify_gtk_step2_called;
/* GTK Handshake 2-of-2 frame we are expected to generate + its size */
static const uint8_t *expected_gtk_step2_frame;
static size_t expected_gtk_step2_frame_size;

/* Authenticator Address */
static const uint8_t *aa;
/* Supplicant Address */
static const uint8_t *spa;

///XXX Global variable for data read from AFL
char * __afl_input_filename = NULL;
uint8_t * __afl_key1;
uint8_t  * __afl_key2;
uint8_t  * __afl_key3;
size_t len_frame1;
size_t len_frame2;
size_t len_frame3;
#define MAX_FRAME 1024




struct test_handshake_state {
    struct handshake_state super;
    const uint8_t *tk;
    bool handshake_failed;
};

static void test_handshake_state_free(struct handshake_state *hs)
{
    struct test_handshake_state *ths =
    container_of(hs, struct test_handshake_state, super);

    l_free(ths);
}

static struct handshake_state *test_handshake_state_new(uint32_t ifindex)
{
    struct test_handshake_state *ths;

    ths = l_new(struct test_handshake_state, 1);

    ths->super.ifindex = ifindex;
    ths->super.free = test_handshake_state_free;

    return &ths->super;
}



struct eapol_key_data {
    const unsigned char *frame;
    size_t frame_len;
    enum eapol_protocol_version protocol_version;
    uint16_t packet_len;
    enum eapol_descriptor_type descriptor_type;
    enum eapol_key_descriptor_version key_descriptor_version;
    bool key_type:1;
    uint8_t wpa_key_id:2;
    bool install:1;
    bool key_ack:1;
    bool key_mic:1;
    bool secure:1;
    bool error:1;
    bool request:1;
    bool encrypted_key_data:1;
    bool smk_message:1;
    uint16_t key_length;
    uint64_t key_replay_counter;
    uint8_t key_nonce[32];
    uint8_t eapol_key_iv[16];
    uint8_t key_rsc[8];
    uint8_t key_mic_data[16];
    uint16_t key_data_len;
};


/* WPA frame, 1 of 4.  For parameters see eapol_sm_test_igtk */
static const unsigned char eapol_key_data_29[] = {
	0x02, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x89, 0x00, 0x20, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x37, 0x86,
	0x8d, 0x6c, 0xd2, 0x38, 0xb2, 0xfe, 0xb4, 0x5b, 0xd3, 0xc6,
	0x4b, 0xa1, 0x3e, 0x26, 0xd9, 0xa4, 0x89, 0x8b, 0x43, 0xf6,
	0x66, 0x51, 0x26, 0x99, 0x5e, 0x62, 0xce, 0x8e, 0x9d, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static struct eapol_key_data eapol_key_test_29 = {
	.frame = eapol_key_data_29,
	.frame_len = sizeof(eapol_key_data_29),
	.protocol_version = EAPOL_PROTOCOL_VERSION_2004,
	.packet_len = 95,
	.descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
	.key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4,
	.key_type = true,
	.install = false,
	.key_ack = true,
	.key_mic = false,
	.secure = false,
	.error = false,
	.request = false,
	.encrypted_key_data = false,
	.smk_message = false,
	.key_length = 32,
	.key_replay_counter = 1,
	.key_nonce = { 0x30, 0x37, 0x86, 0x8d, 0x6c, 0xd2, 0x38, 0xb2, 0xfe,
			0xb4, 0x5b, 0xd3, 0xc6, 0x4b, 0xa1, 0x3e, 0x26, 0xd9,
			0xa4, 0x89, 0x8b, 0x43, 0xf6, 0x66, 0x51, 0x26, 0x99,
			0x5e, 0x62, 0xce, 0x8e, 0x9d},
	.eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_mic_data = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
	.key_data_len = 0,
};

/* WPA frame, 2 of 4.  For parameters see eapol_sm_test_igtk */
static const unsigned char eapol_key_data_30[] = {
	0x01, 0x03, 0x00, 0x7b, 0x02, 0x01, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x3e, 0x5e, 0xb7, 0x47, 0x91, 0xf4, 0x2a,
	0x39, 0x3a, 0x6a, 0xbc, 0xeb, 0x9c, 0x25, 0x27, 0x0f, 0x61, 0xb4, 0x24,
	0x8c, 0xf2, 0x97, 0xdf, 0x22, 0xef, 0x67, 0x15, 0x87, 0xad, 0x22, 0xc3,
	0xd8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x76, 0xec,
	0x87, 0x1e, 0x42, 0x7a, 0x66, 0x3f, 0x45, 0xb2, 0x7f, 0x7c, 0xd7, 0xe3,
	0xb9, 0x00, 0x1c, 0x30, 0x1a, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01,
	0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x0f, 0xac, 0x06,
};

static struct eapol_key_data eapol_key_test_30 = {
	.frame = eapol_key_data_30,
	.frame_len = sizeof(eapol_key_data_30),
	.protocol_version = EAPOL_PROTOCOL_VERSION_2001,
	.packet_len = 123,
	.descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
	.key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4,
	.key_type = true,
	.install = false,
	.key_ack = false,
	.key_mic = true,
	.secure = false,
	.error = false,
	.request = false,
	.encrypted_key_data = false,
	.smk_message = false,
	.key_length = 0,
	.key_replay_counter = 1,
	.key_nonce = { 0x3e, 0x5e, 0xb7, 0x47, 0x91, 0xf4, 0x2a, 0x39, 0x3a,
			0x6a, 0xbc, 0xeb, 0x9c, 0x25, 0x27, 0x0f, 0x61, 0xb4,
			0x24, 0x8c, 0xf2, 0x97, 0xdf, 0x22, 0xef, 0x67, 0x15,
			0x87, 0xad, 0x22, 0xc3, 0xd8 },
	.eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_mic_data = { 0x92, 0x76, 0xec, 0x87, 0x1e, 0x42, 0x7a, 0x66, 0x3f,
			0x45, 0xb2, 0x7f, 0x7c, 0xd7, 0xe3, 0xb9 },
	.key_data_len = 28,
};

/* WPA frame, 3 of 4.  For parameters see eapol_sm_test_igtk */
static const unsigned char eapol_key_data_31[] = {
	0x02, 0x03, 0x00, 0xd3, 0x02, 0x13, 0xc9, 0x00, 0x20, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x30, 0x37, 0x86, 0x8d, 0x6c, 0xd2, 0x38,
	0xb2, 0xfe, 0xb4, 0x5b, 0xd3, 0xc6, 0x4b, 0xa1, 0x3e, 0x26, 0xd9, 0xa4,
	0x89, 0x8b, 0x43, 0xf6, 0x66, 0x51, 0x26, 0x99, 0x5e, 0x62, 0xce, 0x8e,
	0x9d, 0x92, 0xcf, 0x64, 0xa6, 0xf5, 0xea, 0x95, 0xf7, 0xf9, 0xeb, 0x6a,
	0x54, 0x8a, 0x85, 0x6c, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x80, 0xb3,
	0x14, 0x1f, 0xfa, 0x11, 0x47, 0xcd, 0x6d, 0xd0, 0x20, 0x7e, 0x9e, 0x68,
	0x65, 0x00, 0x74, 0x39, 0xf4, 0xc9, 0x3a, 0xf3, 0xac, 0xf5, 0xd3, 0x98,
	0xeb, 0xaf, 0x3c, 0x0f, 0xf1, 0xb5, 0x33, 0xff, 0xb2, 0x00, 0x1b, 0xe4,
	0x2c, 0x61, 0xaf, 0xff, 0x1c, 0x22, 0x76, 0x07, 0x3b, 0xbc, 0x0d, 0x0c,
	0xeb, 0x8a, 0xdc, 0xcd, 0x47, 0x01, 0xa5, 0x6e, 0x76, 0x77, 0x85, 0x6f,
	0x09, 0x43, 0x83, 0xee, 0x50, 0x6e, 0x5e, 0xb1, 0x24, 0xe3, 0x47, 0xef,
	0x20, 0x5e, 0x5c, 0x10, 0x7a, 0xe3, 0x61, 0x69, 0x7b, 0xb0, 0xf6, 0xdd,
	0x42, 0x1a, 0xe1, 0xc9, 0x33, 0xd6, 0xd3, 0x88, 0x40, 0xcc, 0x72, 0x28,
	0x86, 0xce, 0xec, 0xea, 0xc0, 0xea, 0xc9, 0xcf, 0xe1, 0x93, 0x8b, 0x15,
	0x5e, 0xbb, 0x1f, 0xf9, 0x6f, 0x10, 0x34, 0xa5, 0xfc, 0x61, 0x78, 0x77,
	0xa7, 0xb1, 0x4d, 0xc4, 0x36, 0xea, 0x2f, 0x1d, 0xda, 0x31, 0xa1,
};

static struct eapol_key_data eapol_key_test_31 = {
	.frame = eapol_key_data_31,
	.frame_len = sizeof(eapol_key_data_31),
	.protocol_version = EAPOL_PROTOCOL_VERSION_2004,
	.packet_len = 211,
	.descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
	.key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4,
	.key_type = true,
	.install = true,
	.key_ack = true,
	.key_mic = true,
	.secure = true,
	.error = false,
	.request = false,
	.encrypted_key_data = true,
	.smk_message = false,
	.key_length = 32,
	.key_replay_counter = 2,
	.key_nonce = { 0x30, 0x37, 0x86, 0x8d, 0x6c, 0xd2, 0x38, 0xb2, 0xfe,
			0xb4, 0x5b, 0xd3, 0xc6, 0x4b, 0xa1, 0x3e, 0x26, 0xd9,
			0xa4, 0x89, 0x8b, 0x43, 0xf6, 0x66, 0x51, 0x26, 0x99,
			0x5e, 0x62, 0xce, 0x8e, 0x9d },
	.eapol_key_iv = { 0x92, 0xcf, 0x64, 0xa6, 0xf5, 0xea, 0x95, 0xf7, 0xf9,
			0xeb, 0x6a, 0x54, 0x8a, 0x85, 0x6c, 0x1c},
	.key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_mic_data = { 0x1f, 0x80, 0xb3, 0x14, 0x1f, 0xfa, 0x11, 0x47, 0xcd,
			0x6d, 0xd0, 0x20, 0x7e, 0x9e, 0x68, 0x65 },
	.key_data_len = 116,
};

/* WPA frame, 4 of 4.  For parameters see eapol_sm_test_igtk */
static const unsigned char eapol_key_data_32[] = {
	0x01, 0x03, 0x00, 0x5f, 0x02, 0x03, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x2c, 0x07,
	0x9b, 0x73, 0xb6, 0x94, 0xb9, 0x4b, 0x7f, 0xa1, 0x99, 0x2f, 0x7a, 0x92,
	0xe2, 0x00, 0x00
};

static struct eapol_key_data eapol_key_test_32 = {
	.frame = eapol_key_data_32,
	.frame_len = sizeof(eapol_key_data_32),
	.protocol_version = EAPOL_PROTOCOL_VERSION_2001,
	.packet_len = 95,
	.descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
	.key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4,
	.key_type = true,
	.install = false,
	.key_ack = false,
	.key_mic = true,
	.secure = true,
	.error = false,
	.request = false,
	.encrypted_key_data = false,
	.smk_message = false,
	.key_length = 0,
	.key_replay_counter = 2,
	.key_nonce = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.key_mic_data = { 0x66, 0x2c, 0x07, 0x9b, 0x73, 0xb6, 0x94, 0xb9,
			0x4b, 0x7f, 0xa1, 0x99, 0x2f, 0x7a, 0x92, 0xe2  },
	.key_data_len = 0,
};




void * __afl_get_key_data_igtk( ){
    FILE * fp;
    int i;
    int data;
    size_t ret;

    fp = fopen(__afl_input_filename , "rb");
    if (fp == NULL){
        perror("!!! Warning: no input file for AFL. Tests will be executed with static data!!!\n");
        __afl_key1 =(uint8_t*) eapol_key_data_29;
        __afl_key2 =(uint8_t*) eapol_key_data_31;
        __afl_key3 =(uint8_t*) eapol_key_data_31;
        len_frame1= sizeof(eapol_key_data_29);
        len_frame2= sizeof(eapol_key_data_31);
        len_frame3= sizeof(eapol_key_data_31);
        return(NULL);
    }
    else{
        printf("+++ File open correctly! +++\n");
    }

    //printf("Reading Frame 1\n");
    ret = fread(&len_frame1, sizeof(size_t), 1, fp);
    if(ret <= 0 ){
	printf("\n Read len failed!\n");
    	exit(EXIT_FAILURE);
	}

    if(len_frame1 <= 0 || len_frame1 > MAX_FRAME ){
        printf("\nLen frame1 is either < 0 or > of file size! %ld\n",len_frame1 );
        exit(EXIT_FAILURE);

    }

    printf("Frame 1 len: %ld\n\n",len_frame1);

    __afl_key1 = (uint8_t *)malloc(sizeof(uint8_t)* len_frame1);
    for (i=0 ; i < len_frame1; i++){
        ret = fread(&data, sizeof(uint8_t), 1, fp);
       if(ret <= 0 ){
	printf("\n Read data failed!\n");
    	exit(EXIT_FAILURE);
	}
	 __afl_key1[i] = data;
        printf("%d ", __afl_key1[i]);
    }


    ret = fread(&data, sizeof(uint8_t), 1, fp);


    //  printf("\nReading Frame 2\n");
    ret = fread(&len_frame2, sizeof(size_t), 1, fp);
    if(ret <= 0 ){
	printf("\n Read len failed!\n");
    	exit(EXIT_FAILURE);
	}

    if(len_frame2 <= 0 || len_frame2 > MAX_FRAME ){
        printf("\nLen frame2 is either < 0 or > of file size! %ld\n",len_frame2);
        exit(EXIT_FAILURE);
        //return -1;
    }
    printf("\n------------------------------------------------------\n");
    printf("\n");
    printf("Frame 2 len: %ld\n\n",len_frame2);
    __afl_key2 = (uint8_t *)malloc(sizeof(uint8_t)* len_frame2);
    for (i=0 ; i < len_frame2; i++){
        ret = fread(&data, sizeof(uint8_t), 1, fp);
       if(ret <= 0 ){
		printf("\n Read data failed!\n");
    		exit(EXIT_FAILURE);
	}
	 __afl_key2[i] = data;
        printf("%d ", __afl_key2[i]);
    }

    printf("\n");
    printf("\n------------------------------------------------------\n");

    //skip one (Figure it out why)
    ret = fread(&data, sizeof(uint8_t), 1, fp);


    //  printf("\nReading Frame 2\n");
    ret = fread(&len_frame3, sizeof(size_t), 1, fp);
    if(ret <= 0 ){
	printf("\n Read len failed!\n");
    	exit(EXIT_FAILURE);
	}

    if(len_frame3 <= 0 || len_frame3 > MAX_FRAME ){
        printf("\nLen frame2 is either < 0 or > of file size! %ld\n",len_frame3);
        exit(EXIT_FAILURE);
        //return -1;
    }
    printf("\n------------------------------------------------------\n");
    printf("\n");
    printf("Frame 3 len: %ld\n\n",len_frame3);
    __afl_key3 = (uint8_t *)malloc(sizeof(uint8_t)* len_frame3);
    for (i=0 ; i < len_frame3; i++){
        ret = fread(&data, sizeof(uint8_t), 1, fp);
       if(ret <= 0 ){
		printf("\n Read data failed!\n");
    		exit(EXIT_FAILURE);
	}
	 __afl_key3[i] = data;
        printf("%d ", __afl_key3[i]);
    }

    printf("\n");
    printf("\n------------------------------------------------------\n");


    fclose(fp);
    fp = NULL;
    return(NULL);
};


#if 0
static void eapol_key_test(const void *data)
{
    const struct eapol_key_data *test = data;
    const struct eapol_key *packet;

    packet = eapol_key_validate(test->frame, test->frame_len);
    assert(packet);

    assert(packet->header.protocol_version == test->protocol_version);
    assert(packet->header.packet_type == 0x03);
    assert(L_BE16_TO_CPU(packet->header.packet_len) == test->packet_len);
    assert(packet->descriptor_type == test->descriptor_type);
    assert(packet->key_descriptor_version == test->key_descriptor_version);
    assert(packet->key_type == test->key_type);
    assert(packet->wpa_key_id == test->wpa_key_id);
    assert(packet->install == test->install);
    assert(packet->key_ack == test->key_ack);
    assert(packet->key_mic == test->key_mic);
    assert(packet->secure == test->secure);
    assert(packet->error == test->error);
    assert(packet->request == test->request);
    assert(packet->encrypted_key_data == test->encrypted_key_data);
    assert(packet->smk_message == test->smk_message);
    assert(L_BE16_TO_CPU(packet->key_length) == test->key_length);
    assert(L_BE64_TO_CPU(packet->key_replay_counter) ==
           test->key_replay_counter);
    assert(!memcmp(packet->key_nonce, test->key_nonce,
                   sizeof(packet->key_nonce)));
    assert(!memcmp(packet->eapol_key_iv, test->eapol_key_iv,
                   sizeof(packet->eapol_key_iv)));
    assert(!memcmp(packet->key_mic_data, test->key_mic_data,
                   sizeof(packet->key_mic_data)));
    assert(!memcmp(packet->key_rsc, test->key_rsc,
                   sizeof(packet->key_rsc)));
    assert(L_BE16_TO_CPU(packet->key_data_len) == test->key_data_len);
}

#endif

static int verify_step2(uint32_t ifindex,
                        const uint8_t *aa_addr, uint16_t proto,
                        const struct eapol_frame *ef, bool noencrypt,
                        void *user_data)
{

    printf("\nXXX function verify_step2 called XXX \n");
    const struct eapol_key *ek = (const struct eapol_key *) ef;
    size_t ek_len = sizeof(struct eapol_key) +
                    L_BE16_TO_CPU(ek->key_data_len);



    assert(ifindex == 1);
    assert(proto == ETH_P_PAE);
    assert(!memcmp(aa_addr, aa, 6));

    if((ek_len != expected_step2_frame_size)){
        printf("step2 different frame size\n");
       // assert(false);
        //exit(1);
    }
    if(memcmp(ek, expected_step2_frame, expected_step2_frame_size)){
        printf("step2 memcmp failed\n");
       // assert(false);
        //exit(1);

    }

  //  assert(ek_len == expected_step2_frame_size);
  //  assert(!memcmp(ek, expected_step2_frame, expected_step2_frame_size));

    verify_step2_called = true;

    return 0;
}

static int verify_step4(uint32_t ifindex,
                        const uint8_t *aa_addr, uint16_t proto,
                        const struct eapol_frame *ef, bool noencrypt,
                        void *user_data)
{
    printf("\nXXX function verify_step4 called XXX\n");
    const struct eapol_key *ek = (const struct eapol_key *) ef;
    size_t ek_len = sizeof(struct eapol_key) +
                    L_BE16_TO_CPU(ek->key_data_len);

    // AFL: the exact reply should be ignored. As long as there
    // is a reply, we are good.
#if 0
    assert(ifindex == 1);
    assert(!memcmp(aa_addr, aa, 6));
    assert(proto == ETH_P_PAE);

    if((ek_len != expected_step4_frame_size)){
        printf("step4 different frame size\n");
       // assert(false);
        exit(1);
    }
    if(memcmp(ek, expected_step4_frame, expected_step4_frame_size)){
        printf("step4 memcmp failed\n");
        //assert(false);
        exit(1);
    }
#endif

//       assert(ek_len == expected_step4_frame_size);
  //  assert(!memcmp(ek, expected_step4_frame, expected_step4_frame_size));

    verify_step4_called = true;


    return 0;
}
static bool test_nonce(uint8_t nonce[])
{
    memcpy(nonce, snonce, 32);

    return true;
}

static void detect_key_reinstallation(struct handshake_state *hs,
                              const uint8_t *tk, uint32_t cipher)
{
    static uint8_t prev_key[16] = {0};

    if (memcmp(tk, prev_key, 16) == 0) {
        printf("===> Key reinstallation detected!\n");
        assert(0);
    }

    memcpy(prev_key, tk, 16);
}


//XXX FUNCTION UNDER ANALYSIS
static void eapol_sm_test_igtk(const void *data)
{
   const unsigned char psk[] = {
		0xbf, 0x9a, 0xa3, 0x15, 0x53, 0x00, 0x12, 0x5e,
		0x7a, 0x5e, 0xbb, 0x2a, 0x54, 0x9f, 0x8c, 0xd4,
		0xed, 0xab, 0x8e, 0xe1, 0x2e, 0x94, 0xbf, 0xc2,
		0x4b, 0x33, 0x57, 0xad, 0x04, 0x96, 0x65, 0xd9 };
	const unsigned char ap_rsne[] = {
		0x30, 0x1a, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00,
		0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xac, 0x06 };
	static uint8_t ap_address[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static uint8_t sta_address[] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00 };
	bool r;
	struct handshake_state *hs;
	struct eapol_sm *sm;

	eapol_init();

    __afl_get_key_data_igtk();

	snonce = eapol_key_test_30.key_nonce;
	__handshake_set_get_nonce_func(test_nonce);

	aa = ap_address;
	spa = sta_address;
	verify_step2_called = false;
	expected_step2_frame = eapol_key_data_30;
	expected_step2_frame_size = sizeof(eapol_key_data_30);
	verify_step4_called = false;
	expected_step4_frame = eapol_key_data_32;
	expected_step4_frame_size = sizeof(eapol_key_data_32);

	hs = test_handshake_state_new(1);
	sm = eapol_sm_new(hs);
	eapol_register(sm);

	/* key_data_29 uses 2004 while key_data_30 uses 2001, so force 2001 */
	eapol_sm_set_protocol_version(sm, EAPOL_PROTOCOL_VERSION_2001);

	handshake_state_set_pmk(hs, psk, sizeof(psk));
	handshake_state_set_authenticator_address(hs, aa);
	handshake_state_set_supplicant_address(hs, spa);

	r =  handshake_state_set_supplicant_rsn(hs,eapol_key_data_30 + sizeof(struct eapol_key));

    __handshake_set_install_tk_func(detect_key_reinstallation);

    assert(r);

    handshake_state_set_authenticator_rsn(hs, ap_rsne);
    eapol_start(sm);


    __eapol_set_tx_packet_func(verify_step2);
    __eapol_rx_packet(1, aa, ETH_P_PAE,__afl_key1, len_frame1, false);
    //assert(verify_step2_called);

    if(verify_step2_called == true){
        printf("step 2 true\n");
    }

    __eapol_set_tx_packet_func(verify_step4);
    __eapol_rx_packet(1, aa, ETH_P_PAE, __afl_key2, len_frame2, false);
    //assert(verify_step4_called);


    if(verify_step4_called == true){
        printf("step 4 true\n");
    }

    // AFL: inject the second packet a second time. This is to quickly simulate
    // a key reinstallation. This is not ideal.
    __eapol_set_tx_packet_func(verify_step4);
    __eapol_rx_packet(1, aa, ETH_P_PAE, __afl_key3, len_frame3, false);

    //eapol_sm_free(sm);
    //handshake_state_free(hs);
    //printf("Exit from test\n");
    //eapol_exit();
}




int main(int argc, char *argv[])
{
    if (argc >= 1 && argv[1] != NULL) {
        __afl_input_filename = argv[1];
    }



    l_test_init(&argc, &argv);



    if (!l_checksum_is_supported(L_CHECKSUM_MD5, true) ||
        !l_checksum_is_supported(L_CHECKSUM_SHA1, true))
        goto done;


  l_test_add("EAPoL IGTK & 4-Way Handshake",
			&eapol_sm_test_igtk, NULL);

    done:
    return l_test_run();
}



