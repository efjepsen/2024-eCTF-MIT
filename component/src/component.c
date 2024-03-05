/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

// MIT: Includes for our custom features
#include "common_init.h"
#include "common_msg.h"
#include "simple_trng.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

/******************************** TYPE DEFINITIONS ********************************/


/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    mit_packet_t * packet = (mit_packet_t *) transmit_buffer;
    memcpy((void *)packet->message.rawBytes, buffer, len);
    set_ad(packet, MIT_CMD_NONE, len);
    send_packet_and_ack(packet);
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    return wait_and_receive_packet(buffer);
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Output to application processor dependent on command received
    switch (packet->ad.opcode) {
    case MIT_CMD_BOOT:
        process_boot();
        break;
    case MIT_CMD_SCAN:
        process_scan();
        break;
    case MIT_CMD_VALIDATE:
        process_validate();
        break;
    case MIT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", packet->ad.opcode);
        break;
    }
}

void set_ad(mit_packet_t * packet, mit_opcode_t opcode, uint8_t len) {
    packet->ad.nonce.sequenceNumber = 0;
    packet->ad.comp_id = COMPONENT_ID;
    packet->ad.opcode = opcode;
    packet->ad.len = len;
    packet->ad.for_ap = true;
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    mit_packet_t * packet = (mit_packet_t *) transmit_buffer;

    // Copy boot message into message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void *)packet->message.rawBytes, COMPONENT_BOOT_MSG, len);

    // Set AD section
    set_ad(packet, MIT_CMD_BOOT, len);

    send_packet_and_ack(packet);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    mit_packet_t * packet = (mit_packet_t *) transmit_buffer;
    packet->message.component_id = COMPONENT_ID;
    set_ad(packet, MIT_CMD_SCAN, sizeof(mit_comp_id_t));
    send_packet_and_ack(packet);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    mit_packet_t * packet = (mit_packet_t *) transmit_buffer;
    packet->message.component_id = COMPONENT_ID;
    set_ad(packet, MIT_CMD_VALIDATE, sizeof(mit_comp_id_t));
    send_packet_and_ack(packet);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    mit_packet_t * packet = (mit_packet_t *) transmit_buffer;

    uint8_t len = sprintf((char*)packet->message.rawBytes, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    set_ad(packet, MIT_CMD_ATTEST, len);
    send_packet_and_ack(packet);
}

/*********************************** MAIN *************************************/

int main(void) {
    // Enable Global Interrupts
    __enable_irq();

    // MIT: Initialize our custom features
    common_init();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);

        component_process_cmd();
    }
}
