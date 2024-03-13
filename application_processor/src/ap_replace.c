/**
 * @file ap_replace.c
 * @brief Replace-related functions for AP
 */

#include "ap_common.h"

// SALT_LEN + TOKEN_LEN = 48
#define SALT_LEN MIT_HASH_SIZE
#define TOKEN_LEN 16
static uint8_t guess_buf[SALT_LEN + TOKEN_LEN] = REPLACE_SALT;
static uint8_t guessed_hash[MIT_HASH_SIZE] = {0};

// Replace a component if the PIN is correct
void attempt_replace() {
    char * buf = get_uart_buf();

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", 10);  // 0x + 8 chars
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", 10); // 0x + 8 chars
    sscanf(buf, "%x", &component_id_out);

    if (swap_components(component_id_in, component_id_out) == ERROR_RETURN) {
        print_error("Cannot replace component 0x%08x with component 0x%08x\n",
            component_id_out, component_id_in);
        return;
    }

    print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
            component_id_in);
    print_success("Replace\n");
}

int compare_token(char * token) {
    int ret;

    // Copy guess into end of buffer
    memcpy(&guess_buf[MIT_HASH_SIZE], token, TOKEN_LEN);

    // Compute hash over salt + guess
    ret = mit_sha256(guess_buf, SALT_LEN + TOKEN_LEN, guessed_hash);
    if (ret != 0) {
        return ERROR_RETURN;
    }

    uint8_t * hashed_token = getHashedTokenPtr();

    // Compare with precomputed salt+actual_token
    return mit_ConstantCompare(guessed_hash, hashed_token, MIT_HASH_SIZE);
}

// Function to validate the replacement token
int validate_token() {
    char * buf = get_uart_buf();
    recv_input("Enter token: ", TOKEN_LEN);
    if (!compare_token(buf)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}
