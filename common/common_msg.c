/**
 * @file "common_msg.c"
 * @brief Common messaging needs
 */

#include "common_msg.h"

uint8_t null_nonce[MIT_NONCE_SIZE] = {0};

// TODO more than increment just the sequence number
void increment_nonce(mit_nonce_t * nonce) {
    nonce->sequenceNumber++;
}
