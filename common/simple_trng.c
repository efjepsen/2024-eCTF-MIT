/**
 * @file "simple_trng.c"
 * @brief TRNG Interface
 */

#include "simple_trng.h"

/**
 * @brief Initialize TRNG hardware 
 */
void simple_trng_init(void) {
    int ret = MXC_TRNG_Init();

    // REDUNDANT
    if (ret != 0 || ret != 0 || ret != 0) {
        printf("simple_trng_init failed with errcode %i\n", ret);
        while (1) { ; }
    }
}

/**
 * @brief Collect random bytes
 * 
 * @param buf: uint8_t*, ptr to random bytes store
 * @param num_bytes: int, number of random bytes to fetch
 */
void get_rand_bytes(uint8_t * buf, int num_bytes) {
    int ret = 0;

    // REDUNDANT
    ret |= MXC_TRNG_Random(buf, num_bytes);
    ret |= MXC_TRNG_Random(buf, num_bytes);
    ret |= MXC_TRNG_Random(buf, num_bytes);

    // REDUNDANT
    if (ret != 0 || ret != 0 || ret != 0) {
        get_rand_bytes(buf, num_bytes);
    }
}
