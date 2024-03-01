/**
 * @file host_messaging.c
 * @author Frederich Stine
 * @brief eCTF Host Messaging Implementation 
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "host_messaging.h"

// Print a message through USB UART and then receive a line over USB UART
void recv_input(const char *msg, char *buf) {
    print_debug(msg);
    fflush(0);
    print_ack();

    // Read one character at a time until newline or EOF
    int idx = 0, c = 0;
    while ((c = getchar()) != '\n' && c != EOF) {
        // UART_MAX_LEN - 1 so we can always append the null-byte later
        buf[idx % (UART_MAX_LEN - 1)] = (char)c;
        idx++;
    }

    // Append null-byte to end the string :)
    buf[idx % UART_MAX_LEN] = '\0';

    puts("");
}

// Prints a buffer of bytes as a hex string
void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}
