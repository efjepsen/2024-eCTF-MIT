/**
 * @file "common_crypto.c"
 * @brief Common crypto needs
 */

#include "common_crypto.h"

// TODO check for null nonces

int mit_encrypt(mit_packet_t * packet, uint8_t * plaintext, uint8_t len) {

    const uint8_t * iv    = packet->ad.nonce.rawBytes;
    const uint8_t * inAAD = &packet->ad;
    uint8_t * ciphertext  = packet->message.rawBytes;
    uint8_t * authTag     = packet->authTag.rawBytes;

    return wc_ChaCha20Poly1305_Encrypt(
        SHARED_SECRET_KEY, iv, // key, iv
        inAAD, sizeof(mit_ad_t),  // ad, len(ad)
        plaintext, len,        // plaintext, len(plaintext),
        ciphertext, authTag    // ciphertext, authTag
    );
}

int mit_decrypt(mit_packet_t * packet, uint8_t * plaintext) {

    const uint8_t * iv    = packet->ad.nonce.rawBytes;
    const uint8_t * inAAD = &packet->ad;
    const uint8_t * ciphertext  = packet->message.rawBytes;
    const uint8_t * authTag     = packet->authTag.rawBytes;
    const uint8_t len           = packet->ad.len;

    return wc_ChaCha20Poly1305_Decrypt(
        SHARED_SECRET_KEY, iv,
        inAAD, sizeof(mit_ad_t),
        ciphertext, len,
        authTag, plaintext
    );
}
