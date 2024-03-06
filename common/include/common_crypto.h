/**
 * @file "common_crypto.h"
 * @brief Common crypto structs
 */

#ifndef _COMMON_CRYPTO_H_
#define _COMMON_CRYPTO_H_

#include "global_secrets.h"
#include "common_msg.h"

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

int mit_encrypt(mit_packet_t * packet, uint8_t * plaintext, uint8_t len);
int mit_decrypt(mit_packet_t * packet, uint8_t * plaintext);

#endif