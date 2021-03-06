/*  !!!! TEST-EAPOL WPA2 PTK/GTK !!!!
 *
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
uint8_t * __afl_key2;
uint8_t * __afl_key3;
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


/* WPA2 frame, 1 of 4.  For parameters see eapol_wpa2_handshake_test */
static const unsigned char eapol_key_data_7[] = {
        0x02, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x2b, 0x58, 0x52, 0xb8, 0x8e, 0x4c, 0xa3,
        0x4d, 0xc5, 0x99, 0xed, 0x20, 0x2c, 0x63, 0x95, 0x7c, 0x53, 0x5e, 0x3e,
        0xfa, 0x92, 0x89, 0x87, 0x34, 0x11, 0x12, 0x7c, 0xba, 0xf3, 0x58, 0x84,
        0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
};


static struct eapol_key_data eapol_key_test_7 = {
        .frame = eapol_key_data_7,
        .frame_len = sizeof(eapol_key_data_7),
        .protocol_version = EAPOL_PROTOCOL_VERSION_2004,
        .packet_len = 95,
        .descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
        .key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES,
        .key_type = true,
        .wpa_key_id = 0,
        .install = false,
        .key_ack = true,
        .key_mic = false,
        .secure = false,
        .error = false,
        .request = false,
        .encrypted_key_data = false,
        .smk_message = false,
        .key_length = 16,
        .key_replay_counter = 1,
        .key_nonce = { 0x2b, 0x58, 0x52, 0xb8, 0x8e, 0x4c, 0xa3, 0x4d, 0xc5,
                       0x99, 0xed, 0x20, 0x2c, 0x63, 0x95, 0x7c, 0x53, 0x5e,
                       0x3e, 0xfa, 0x92, 0x89, 0x87, 0x34, 0x11, 0x12, 0x7c,
                       0xba, 0xf3, 0x58, 0x84, 0x25 },
        .eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_mic_data = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_data_len = 0,
};

/* WPA2 frame, 2 of 4.  For parameters see eapol_wpa2_handshake_test */
static const unsigned char eapol_key_data_8[] = {
        0x02, 0x03, 0x00, 0x73, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x72, 0x7c, 0x65, 0x6c, 0x5e, 0xd6, 0x42,
        0xd7, 0xf4, 0x7f, 0x48, 0x43, 0x51, 0xd8, 0x08, 0x94, 0x51, 0x18, 0xda,
        0x6a, 0x49, 0x33, 0xac, 0x7e, 0x29, 0x3f, 0x2f, 0x2a, 0xc0, 0x88, 0x34,
        0x8c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7d, 0x7c, 0x45,
        0x98, 0x9f, 0x49, 0x2b, 0x4a, 0x36, 0x58, 0x35, 0x29, 0x28, 0x2d, 0x8f,
        0xed, 0x00, 0x14, 0x30, 0x12, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02
};

static struct eapol_key_data eapol_key_test_8 = {
        .frame = eapol_key_data_8,
        .frame_len = sizeof(eapol_key_data_8),
        .protocol_version = EAPOL_PROTOCOL_VERSION_2004,
        .packet_len = 115,
        .descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
        .key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES,
        .key_type = true,
        .wpa_key_id = 0,
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
        .key_nonce = { 0x72, 0x7c, 0x65, 0x6c, 0x5e, 0xd6, 0x42, 0xd7, 0xf4,
                       0x7f, 0x48, 0x43, 0x51, 0xd8, 0x08, 0x94, 0x51, 0x18,
                       0xda, 0x6a, 0x49, 0x33, 0xac, 0x7e, 0x29, 0x3f, 0x2f,
                       0x2a, 0xc0, 0x88, 0x34, 0x8c },
        .eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_mic_data = { 0x7d, 0x7c, 0x45, 0x98, 0x9f, 0x49, 0x2b, 0x4a,
                          0x36, 0x58, 0x35, 0x29, 0x28, 0x2d, 0x8f, 0xed },
        .key_data_len = 20,
};

/* WPA2 frame, 3 of 4.  For parameters see eapol_wpa2_handshake_test */
static const unsigned char eapol_key_data_9[] = {
        0x02, 0x03, 0x00, 0x97, 0x02, 0x13, 0xca, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x2b, 0x58, 0x52, 0xb8, 0x8e, 0x4c, 0xa3,
        0x4d, 0xc5, 0x99, 0xed, 0x20, 0x2c, 0x63, 0x95, 0x7c, 0x53, 0x5e, 0x3e,
        0xfa, 0x92, 0x89, 0x87, 0x34, 0x11, 0x12, 0x7c, 0xba, 0xf3, 0x58, 0x84,
        0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x62, 0x6a,
        0x57, 0x76, 0xc7, 0x33, 0xbf, 0xc0, 0x71, 0xde, 0x62, 0xeb, 0xf7, 0xa7,
        0xc5, 0x00, 0x38, 0x14, 0xdd, 0x52, 0x80, 0x3d, 0xc8, 0x3d, 0xf7, 0xba,
        0x7e, 0xb6, 0x48, 0x29, 0x6d, 0x65, 0x0e, 0x88, 0xcc, 0xc8, 0xdd, 0x67,
        0x62, 0x04, 0xa2, 0xc7, 0xc1, 0xf2, 0x65, 0x0b, 0xca, 0xf9, 0x6b, 0x66,
        0xf5, 0xb4, 0x3d, 0x99, 0x26, 0xad, 0xc5, 0xce, 0x18, 0xc0, 0xa9, 0x9b,
        0xe5, 0x0e, 0x50, 0x85, 0x84, 0xb1, 0x57, 0xe3, 0x7a, 0x5e, 0x0f
};

static struct eapol_key_data eapol_key_test_9 = {
        .frame = eapol_key_data_9,
        .frame_len = sizeof(eapol_key_data_9),
        .protocol_version = EAPOL_PROTOCOL_VERSION_2004,
        .packet_len = 151,
        .descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
        .key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES,
        .key_type = true,
        .wpa_key_id = 0,
        .install = true,
        .key_ack = true,
        .key_mic = true,
        .secure = true,
        .error = false,
        .request = false,
        .encrypted_key_data = true,
        .smk_message = false,
        .key_length = 16,
        .key_replay_counter = 2,
        .key_nonce = { 0x2b, 0x58, 0x52, 0xb8, 0x8e, 0x4c, 0xa3, 0x4d, 0xc5,
                       0x99, 0xed, 0x20, 0x2c, 0x63, 0x95, 0x7c, 0x53, 0x5e,
                       0x3e, 0xfa, 0x92, 0x89, 0x87, 0x34, 0x11, 0x12, 0x7c,
                       0xba, 0xf3, 0x58, 0x84, 0x25 },
        .eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_mic_data = { 0xf8, 0x62, 0x6a, 0x57, 0x76, 0xc7, 0x33, 0xbf,
                          0xc0, 0x71, 0xde, 0x62, 0xeb, 0xf7, 0xa7, 0xc5 },
        .key_data_len = 56,
};

/* WPA2 frame, 4 of 4.  For parameters see eapol_wpa2_handshake_test */
static const unsigned char eapol_key_data_10[] = {
        0x02, 0x03, 0x00, 0x5f, 0x02, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x0f, 0x34,
        0x23, 0x49, 0xf0, 0x85, 0x03, 0xe5, 0xfc, 0x54, 0xb7, 0x2c, 0xb5, 0x32,
        0x66, 0x00, 0x00
};

static struct eapol_key_data eapol_key_test_10 = {
        .frame = eapol_key_data_10,
        .frame_len = sizeof(eapol_key_data_10),
        .protocol_version = EAPOL_PROTOCOL_VERSION_2004,
        .packet_len = 95,
        .descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
        .key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES,
        .key_type = true,
        .wpa_key_id = 0,
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
        .key_mic_data = { 0x8b, 0x0f, 0x34, 0x23, 0x49, 0xf0, 0x85, 0x03,
                          0xe5, 0xfc, 0x54, 0xb7, 0x2c, 0xb5, 0x32, 0x66 },
        .key_data_len = 0,
};

/* WPA2 frame, 1 of 2.  For parameters see eapol_wpa2_handshake_test */
static const unsigned char eapol_key_data_11[] = {
        0x02, 0x03, 0x00, 0x7f, 0x02, 0x13, 0x82, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0xef, 0x6d, 0xc2, 0x0c, 0x57, 0x27, 0xe8,
        0x25, 0x07, 0x75, 0x1e, 0x67, 0x36, 0x9d, 0xc9, 0x1e, 0xf1, 0x71, 0x8e,
        0xb1, 0x35, 0xb2, 0x12, 0xdf, 0x9f, 0xcb, 0x0a, 0x65, 0xa2, 0xd5, 0x67,
        0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x6a, 0xb0,
        0x75, 0xbc, 0x8e, 0xd1, 0x92, 0x11, 0xcd, 0xc3, 0xb0, 0xe2, 0xd6, 0x7e,
        0xcf, 0x00, 0x20, 0xe9, 0x96, 0x5b, 0x46, 0x85, 0xd5, 0x8b, 0x88, 0xbd,
        0x57, 0x48, 0x57, 0xe4, 0xf0, 0xdf, 0xdd, 0xf7, 0x2a, 0x7a, 0xa8, 0xeb,
        0x68, 0xa9, 0xef, 0x44, 0x04, 0xa6, 0x6f, 0xaa, 0x48, 0x51, 0x1b
};

static struct eapol_key_data eapol_key_test_11 = {
        .frame = eapol_key_data_11,
        .frame_len = sizeof(eapol_key_data_11),
        .protocol_version = EAPOL_PROTOCOL_VERSION_2004,
        .packet_len = 127,
        .descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
        .key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES,
        .key_type = false,
        .wpa_key_id = 0,
        .install = false,
        .key_ack = true,
        .key_mic = true,
        .secure = true,
        .error = false,
        .request = false,
        .encrypted_key_data = true,
        .smk_message = false,
        .key_length = 16,
        .key_replay_counter = 3,
        .key_nonce = { 0xef, 0x6d, 0xc2, 0x0c, 0x57, 0x27, 0xe8, 0x25,
                       0x07, 0x75, 0x1e, 0x67, 0x36, 0x9d, 0xc9, 0x1e,
                       0xf1, 0x71, 0x8e, 0xb1, 0x35, 0xb2, 0x12, 0xdf,
                       0x9f, 0xcb, 0x0a, 0x65, 0xa2, 0xd5, 0x67, 0x1d },
        .eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_mic_data = { 0x0f, 0x6a, 0xb0, 0x75, 0xbc, 0x8e, 0xd1, 0x92,
                          0x11, 0xcd, 0xc3, 0xb0, 0xe2, 0xd6, 0x7e, 0xcf },
        .key_data_len = 32,
};

/* WPA2 frame, 2 of 2.  For parameters see eapol_wpa2_handshake_test */
static const unsigned char eapol_key_data_12[] = {
        0x02, 0x03, 0x00, 0x5f, 0x02, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc9, 0xbd, 0x17,
        0xf1, 0x54, 0xb7, 0x32, 0xcf, 0xbc, 0x01, 0xdb, 0x0c, 0x37, 0xe6, 0x33,
        0x9f, 0x00, 0x00
};

static struct eapol_key_data eapol_key_test_12 = {
        .frame = eapol_key_data_12,
        .frame_len = sizeof(eapol_key_data_12),
        .protocol_version = EAPOL_PROTOCOL_VERSION_2004,
        .packet_len = 95,
        .descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211,
        .key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES,
        .key_type = false,
        .wpa_key_id = 0,
        .install = false,
        .key_ack = false,
        .key_mic = true,
        .secure = true,
        .error = false,
        .request = false,
        .encrypted_key_data = false,
        .smk_message = false,
        .key_length = 0,
        .key_replay_counter = 3,
        .key_nonce = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .eapol_key_iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_rsc = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        .key_mic_data = { 0xc9, 0xbd, 0x17, 0xf1, 0x54, 0xb7, 0x32, 0xcf,
                          0xbc, 0x01, 0xdb, 0x0c, 0x37, 0xe6, 0x33, 0x9f },
        .key_data_len = 0,
};



void * __afl_get_key_wpa_ptk_gtk( ){
    FILE *fp = NULL;
    int i;
    int data;
    size_t ret;

    fp = fopen(__afl_input_filename , "rb");
    if (fp == NULL){
        perror("!!! Warning: no input file for AFL. Tests will be executed with static data!!!\n");
	 __afl_key1 =(uint8_t*) eapol_key_data_7;
        __afl_key2= (uint8_t*)eapol_key_data_9;
        __afl_key3= (uint8_t*)eapol_key_data_11;
        len_frame1= sizeof(eapol_key_data_7);
        len_frame2= sizeof(eapol_key_data_9);
        len_frame3= sizeof(eapol_key_data_11);
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


static int verify_step2(uint32_t ifindex,
                        const uint8_t *aa_addr, uint16_t proto,
                        const struct eapol_frame *ef, bool noencrypt,
                        void *user_data)
{

   
    const struct eapol_key *ek = (const struct eapol_key *) ef;
    size_t ek_len = sizeof(struct eapol_key) +
                    L_BE16_TO_CPU(ek->key_data_len);

  printf("--- Calling verify_step2() --- \n");
    assert(ifindex == 1);
    assert(proto == ETH_P_PAE);
    assert(!memcmp(aa_addr, aa, 6));
  
    printf("!!Step 2 -> eklen %d, %d\n", ek_len,expected_step2_frame_size);

    if((ek_len != expected_step2_frame_size)){
        printf("step2 different frame size\n");
       // assert(false);
       // exit(1);
    }
    if(memcmp(ek, expected_step2_frame, expected_step2_frame_size)){
        printf("step2 memcmp failed\n");
       // assert(false);
        //exit(1);
    }

  //  assert(ek_len == expected_step2_frame_size);
  // assert(!memcmp(ek, expected_step2_frame, expected_step2_frame_size));

    verify_step2_called = true;

    return 0;
}

static int verify_step4(uint32_t ifindex,
                        const uint8_t *aa_addr, uint16_t proto,
                        const struct eapol_frame *ef, bool noencrypt,
                        void *user_data)
{
    
    const struct eapol_key *ek = (const struct eapol_key *) ef;
    size_t ek_len = sizeof(struct eapol_key) +
                    L_BE16_TO_CPU(ek->key_data_len);

    printf("--- Calling verify_step4() --- \n");
    assert(ifindex == 1);
    assert(!memcmp(aa_addr, aa, 6));
    assert(proto == ETH_P_PAE);

    printf("Step4-> eklen %d, %d\n", ek_len,expected_step4_frame_size);

    if((ek_len != expected_step4_frame_size)){
        printf("step4 different frame size\n");
       // assert(false);
       // exit(1);
    }
    if(memcmp(ek, expected_step4_frame, expected_step4_frame_size)){
        printf("step4 memcmp failed\n");
        //assert(false);
       // exit(1);
    }

//      assert(ek_len == expected_step4_frame_size);
//   assert(!memcmp(ek, expected_step4_frame, expected_step4_frame_size));


    verify_step4_called = true;
    return 0;
}


static int verify_step2_gtk(uint32_t ifindex,
                            const uint8_t *aa_addr, uint16_t proto,
                            const struct eapol_frame *ef, bool noencrypt,
                            void *user_data)
{
    const struct eapol_key *ek = (const struct eapol_key *) ef;
    size_t ek_len = sizeof(struct eapol_key) +
                    L_BE16_TO_CPU(ek->key_data_len);

printf("--- Calling verify_step-gtk() --- \n");
    assert(ifindex == 1);
    assert(!memcmp(aa_addr, aa, 6));
    assert(proto == ETH_P_PAE);

    printf("Stepgtk-> eklen %d, %d\n", ek_len,expected_gtk_step2_frame_size);

    if((ek_len != expected_gtk_step2_frame_size)){
        printf("gtk-step2 different frame size\n");
       // assert(false);
      //  exit(1);
    }
    if(memcmp(ek, expected_gtk_step2_frame, expected_gtk_step2_frame_size)){
        printf("gtk-step2 memcmp failed\n");
        //assert(false);
       // exit(1);
    }


    //assert(ek_len == expected_gtk_step2_frame_size);
    //assert(!memcmp(ek, expected_gtk_step2_frame, expected_gtk_step2_frame_size));

    verify_gtk_step2_called = true;

    return 0;
}

static bool test_nonce(uint8_t nonce[])
{
    memcpy(nonce, snonce, 32);

    return true;
}



static void eapol_sm_test_wpa2_ptk_gtk(const void *data)
{
    const unsigned char psk[] = {
            0xbf, 0x9a, 0xa3, 0x15, 0x53, 0x00, 0x12, 0x5e,
            0x7a, 0x5e, 0xbb, 0x2a, 0x54, 0x9f, 0x8c, 0xd4,
            0xed, 0xab, 0x8e, 0xe1, 0x2e, 0x94, 0xbf, 0xc2,
            0x4b, 0x33, 0x57, 0xad, 0x04, 0x96, 0x65, 0xd9 };
    const unsigned char ap_rsne[] = {
            0x30, 0x12, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
            0x00, 0x0f, 0xac, 0x02 };
    static uint8_t ap_address[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static uint8_t sta_address[] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00 };
    bool r;
    struct handshake_state *hs;
    struct eapol_sm *sm;

    eapol_init();
    __afl_get_key_wpa_ptk_gtk();

    snonce = eapol_key_test_8.key_nonce;
    __handshake_set_get_nonce_func(test_nonce);

    aa = ap_address;
    spa = sta_address;
    verify_step2_called = false;
    expected_step2_frame = eapol_key_data_8;
    expected_step2_frame_size = sizeof(eapol_key_data_8);
    verify_step4_called = false;
    expected_step4_frame = eapol_key_data_10;
    expected_step4_frame_size = sizeof(eapol_key_data_10);
    verify_gtk_step2_called = false;
    expected_gtk_step2_frame = eapol_key_data_12;
    expected_gtk_step2_frame_size = sizeof(eapol_key_data_12);


    printf("DEBUG: ex_step2 %d, ex_step4 %d, ex_gtk %d\n",expected_step2_frame_size,expected_step4_frame_size,expected_gtk_step2_frame_size);

    hs = test_handshake_state_new(1);
    sm = eapol_sm_new(hs);
    eapol_register(sm);

    handshake_state_set_pmk(hs, psk, sizeof(psk));
    handshake_state_set_authenticator_address(hs, aa);
    handshake_state_set_supplicant_address(hs, spa);

    r = handshake_state_set_supplicant_rsn(hs,eapol_key_data_8 + sizeof(struct eapol_key));
    assert(r);

    handshake_state_set_authenticator_rsn(hs, ap_rsne);
    eapol_start(sm);

    __eapol_set_tx_packet_func(verify_step2);
   __eapol_rx_packet(1, aa, ETH_P_PAE, __afl_key1, len_frame1, false);
   // assert(verify_step2_called);
   if(verify_step2_called == true){
        printf("step 2 true\n");
    }

    __eapol_set_tx_packet_func(verify_step4);
  __eapol_rx_packet(1, aa, ETH_P_PAE, __afl_key2, len_frame2, false);
  //  assert(verify_step4_called);
  if(verify_step4_called == true){
        printf("step 4 true\n");
    }

    __eapol_set_tx_packet_func(verify_step2_gtk);
    __eapol_rx_packet(1, aa, ETH_P_PAE, __afl_key3, len_frame3, false);
   // assert(verify_gtk_step2_called);
   if(verify_gtk_step2_called == true){
        printf("gtk_step 2 true\n");
    }

    //printf("-- Calling second eapol_destroy\n");
    //eapol_sm_free(sm);
    //printf("-- Calling handshake state free \n");
    //handshake_state_free(hs);
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


   l_test_add("EAPoL/WPA2 PTK & GTK State Machine", &eapol_sm_test_wpa2_ptk_gtk, NULL);

    done:
    return l_test_run();
}



