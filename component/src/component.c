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
#include "common_crypto.h"
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
int component_process_cmd(void);
int process_boot(void);
int process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* MIT UTILITIES ********************************/

#define COMP_PLAINTEXT_LEN 256

 // TODO gross data allocation ?
uint8_t working_buffer[MIT_MAX_MSG_LEN];
uint8_t comp_plaintext[COMP_PLAINTEXT_LEN];

mit_session_t session;

void session_init(void) {
    // Initialize nonce's to {0}.
    memset(session.rawBytes, 0, sizeof(mit_session_t));

    // Initialize outgoing nonce to some random value
    while (mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, null_nonce) == 0) {
        get_rand_bytes(session.outgoing_nonce.rawBytes, MIT_NONCE_SIZE);
    }
}

bool valid_session(void) {
    return mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, null_nonce) != 0;
}

int validate_packet(mit_opcode_t opcode) {
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    if (packet->ad.comp_id != COMPONENT_ID) {
        printf("component_id mismatch\n");
        return ERROR_RETURN;
    }

    if (packet->ad.for_ap != false) {
        printf("for_ap is true\n");
        return ERROR_RETURN;
    }

    // TODO use length-lookup struct
    if (packet->ad.len == 0) {
        printf("len not 0\n");
        return ERROR_RETURN;
    }

    if (packet->ad.opcode != opcode) {
        printf("opcode mismatch\n");
        return ERROR_RETURN;
    }

    // Check received nonce matches expected nonce
    if (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0) {
        printf("nonce mismatch\n");
        printf("packet->ad.nonce.rawBytes: 0x%08x\n", packet->ad.nonce.sequenceNumber);
        printf("session.incoming_nonce.rawBytes: 0x%08x\n", session.incoming_nonce.sequenceNumber);
        return ERROR_RETURN;
    }

    // TODO best place for this?
    increment_nonce(&session.incoming_nonce);

    return SUCCESS_RETURN;
}

void set_ad(mit_packet_t * packet, mit_comp_id_t comp_id, mit_opcode_t opcode, uint8_t len) {
    // TODO limits check on len?
    packet->ad.nonce.sequenceNumber = 0; // TODO
    packet->ad.comp_id = comp_id;
    packet->ad.opcode = opcode;
    packet->ad.len = len;
    packet->ad.for_ap = true; // TODO use ifdefs w/ AP_BOOT_MSG to resolve this in common code?
}

/**
 * @brief Helper for constructing packets
 * 
 * @param component_id: mit_comp_id_t, id of component to make packet for
 * @param opcode: mit_opcode_t, opcode to make packet for
 * @param data: uint8_t *, ptr for data to store in message ield
 * @param len: uint8_t, len of data to copy into message field
 */
int make_mit_packet(mit_comp_id_t component_id, mit_opcode_t opcode, uint8_t * data, uint8_t len) {
    int ret;

    // TODO bounds check on len?
    mit_packet_t * packet = (mit_packet_t *)transmit_buffer;

    // Set Authenticated Data field
    set_ad(packet, component_id, opcode, len);

    /***** NONCE GENERATION/LOOKUP *****/

    // WARNING reusing a nonce is the worst thing you can possibly do.

    // if the nonce is 0, generate a random nonce
    while (mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, null_nonce) == 0) {
        get_rand_bytes(session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    }

    memcpy(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    // TODO do we really need this :)
    if (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes) != 0) {
        printf("error: Failed to copy nonce!\n");
        return ERROR_RETURN;
    }

    /****************************/

    // Encrypt in data
    ret = mit_encrypt(packet, data, len);
    if (ret != SUCCESS_RETURN) {
        printf("error: encryption failed with error code %i\n", ret);
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    // TODO best place to increase nonce?
    increment_nonce(&session.outgoing_nonce);

    return SUCCESS_RETURN;
}

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
    // TODO gross allocation
    make_mit_packet(COMPONENT_ID, MIT_CMD_POSTBOOT, buffer, len);
    send_packet_and_ack((mit_packet_t *)transmit_buffer);
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
    int ret;
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    uint8_t len = wait_and_receive_packet(packet);

   /*************** VALIDATE RECEIVED PACKET ****************/

    if (packet->ad.comp_id != COMPONENT_ID) {
        printf("err: rx packet (0x%08x) doesn't match given component id (0x%08x)\n", packet->ad.comp_id, COMPONENT_ID);
        return ERROR_RETURN;
    }

    if (packet->ad.for_ap != false) {
        printf("err: rx packet not tagged for component\n");
        return ERROR_RETURN;
    }

    if (packet->ad.len == 0) {
        printf("err: rx packet has null message length\n");
        return ERROR_RETURN;
    }

    // TODO validate opcode!
    if (packet->ad.opcode != MIT_CMD_POSTBOOT) {
        printf("err: secure_send: bad opcode 0x%02x\n", packet->ad.comp_id);
        return ERROR_RETURN;
    }

    // Validate incoming nonce matches expected nonce
    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, packet->ad.nonce.rawBytes) == 0) {
        ret = mit_decrypt(packet, comp_plaintext);

        if (ret != SUCCESS_RETURN) {
            printf("err: secure_receive: decryption failed with error %i\n", ret);
            memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
            return ERROR_RETURN;
        }
    } else {
        printf("err: Incoming nonce (seq 0x%08x) doesn't match expected nonce (seq 0x%08x)\n",
            packet->ad.nonce.sequenceNumber, session.incoming_nonce.sequenceNumber
        );
        return ERROR_RETURN;
    }

    // TODO best place for this?
    // increase incoming nonce
    increment_nonce(&session.incoming_nonce);

    /********************************************************/
    memcpy(buffer, comp_plaintext, len);

    return len;
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
int component_process_cmd() {
    int ret;
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Can't hurt to check, just once more.
    if (!valid_session()) {
        return ERROR_RETURN;
    }

    /*************** VALIDATE RECEIVED PACKET ****************/
    if (packet->ad.comp_id != COMPONENT_ID) {
        printf("error: rx packet (0x%08x) doesn't match given component id (0x%08x)\n", packet->ad.comp_id, COMPONENT_ID);
        return ERROR_RETURN;
    }

    // TODO use ifdefs for this section
    if (packet->ad.for_ap != false) {
        printf("error: rx packet not tagged for component\n");
        return ERROR_RETURN;
    }

    if (packet->ad.len == 0) {
        printf("error: rx packet has null message length\n");
        return ERROR_RETURN;
    }

    // Validate incoming nonce matches expected nonce
    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, packet->ad.nonce.rawBytes) == 0) {
        ret = mit_decrypt(packet, comp_plaintext);

        if (ret != SUCCESS_RETURN) {
            printf("error: decryption failed with error code %i\n", ret);
            memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
            return ERROR_RETURN;
        }
    } else {
        printf("error: Incoming nonce (seq 0x%08x) doesn't match expected nonce (seq 0x%08x)\n",
            packet->ad.nonce.sequenceNumber, session.incoming_nonce.sequenceNumber
        );
        return ERROR_RETURN;
    }

    // TODO best place for this?
    // increment_nonce(&session.incoming_nonce);

    // Output to application processor dependent on command received
    switch (packet->ad.opcode) {
    case MIT_CMD_BOOTREQ:
        return process_boot();
    case MIT_CMD_ATTESTREQ:
        return process_attest();
    default:
        printf("Error: Unrecognized command received %d\n", packet->ad.opcode);
        return ERROR_RETURN;
    }
}

int process_boot() {
    int ret;
    uint8_t len;
    mit_challenge_t r1, r2;
    mit_message_t * message = (mit_message_t *)comp_plaintext;

    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Step 0: validate packet again :-)
    ret = validate_packet(MIT_CMD_BOOTREQ);
    if (ret != SUCCESS_RETURN) {
        printf("validation failed\n");
        return ERROR_RETURN;
    }

    ret = mit_decrypt(packet, comp_plaintext);
    if (ret != SUCCESS_RETURN) {
        printf("decryption failed\n");
        return ERROR_RETURN;
    }

    // Step 1: Generate random challenge r2
    get_random_challenge(&r2);

    // Step 2: Store r2 in response packet
    memcpy(message->bootReq.r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));

    // Step 3: Send response packet
    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_BOOTREQ, message->bootReq.rawBytes, sizeof(mit_message_bootreq_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);

    // Step 4: Wait to receive a packet
    len = wait_and_receive_packet(receive_buffer);
    if (len <= sizeof(mit_comp_id_t)) {
        return ERROR_RETURN;
    }

    // Step 5: Validate packet
    ret = validate_packet(MIT_CMD_BOOT);
    if (ret != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    ret = mit_decrypt(packet, comp_plaintext);
    if (ret != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    // Step 6: Validate r2 in attest response
    if (mit_ConstantCompare_challenge(message->boot.r2.rawBytes, r2.rawBytes) != 0) {
        return ERROR_RETURN;
    }

    // Step 7: Stuff with boot message
    memset(message->boot.rawBytes, 0, sizeof(mit_message_boot_t));
    len = sprintf(message->boot.bootMsg, "%s", COMPONENT_BOOT_MSG) + 1;

    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_BOOT, message->boot.rawBytes, sizeof(mit_message_boot_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);
    // Call the boot function
    boot();

    // We should never reach this.
    return ERROR_RETURN;
}

int process_attest() {
    int ret;
    uint8_t len;
    mit_challenge_t r1, r2;

    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Step 0: validate packet again :-)
    ret = validate_packet(MIT_CMD_ATTESTREQ);
    if (ret != SUCCESS_RETURN) {
        printf("validation failed\n");
        return ERROR_RETURN;
    }

    ret = mit_decrypt(packet, comp_plaintext);
    if (ret != SUCCESS_RETURN) {
        printf("decryption failed\n");
        return ERROR_RETURN;
    }

    // Step 1: Generate random challenge r2
    get_random_challenge(&r2);

    // Step 2: Store r2 in response packet
    mit_message_attestreq_t * attestReq = (mit_message_attestreq_t *)comp_plaintext;
    memcpy(attestReq->r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));

    // Step 3: Send response packet
    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_ATTESTREQ, attestReq->rawBytes, sizeof(mit_message_attestreq_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);

    // Step 4: Wait to receive a packet
    len = wait_and_receive_packet(receive_buffer);
    if (len <= sizeof(mit_comp_id_t)) {
        return ERROR_RETURN;
    }

    // Step 5: Validate packet
    ret = validate_packet(MIT_CMD_ATTEST);
    if (ret != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    ret = mit_decrypt(packet, comp_plaintext);
    if (ret != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    // Step 6: Validate r2 in attest response
    mit_message_attest_t * attest = (mit_message_attest_t *)comp_plaintext;
    if (mit_ConstantCompare_challenge(attest->r2.rawBytes, r2.rawBytes) != 0) {
        return ERROR_RETURN;
    }

    // Step 7: Stuff with attestation data
    memset(attest->rawBytes, 0, sizeof(mit_message_attest_t));
    len = sprintf(attest->customerData, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;

    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_ATTEST, attest->rawBytes, sizeof(mit_message_attest_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);

    return SUCCESS_RETURN;
}

int process_init_session() {
    // Just double-check :)
    if (valid_session()) {
        return ERROR_RETURN;
    }

    int ret;
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    printf("process_init_session\n");

    /*************** VALIDATE RECEIVED PACKET ****************/
    if (packet->ad.comp_id != COMPONENT_ID) {
        printf("error: rx packet (0x%08x) doesn't match given component id (0x%08x)\n", packet->ad.comp_id, COMPONENT_ID);
        return ERROR_RETURN;
    }

    // TODO use ifdefs for this section
    if (packet->ad.for_ap != false) {
        printf("error: rx packet not tagged for component\n");
        return ERROR_RETURN;
    }

    if (packet->ad.len != sizeof(mit_message_init_t)) {
        printf("error: rx packet has incorrect message length\n");
        return ERROR_RETURN;
    }

    if (packet->ad.opcode != MIT_CMD_INIT) {
        printf("error: rx packet has non-init opcode\n");
        return ERROR_RETURN;
    }

    // Validate authTag field
    ret = mit_decrypt(packet, comp_plaintext);
    if (ret != SUCCESS_RETURN) {
        printf("error: decryption failed with error code %i\n", ret);
        memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    mit_message_init_t * received = (mit_message_init_t *)comp_plaintext;
    if (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->ap_nonce.rawBytes) != 0) {
        // If packet's nonce, and the message's ap_nonce don't match, ignore.
        return ERROR_RETURN;
    }

    // Save incoming nonce
    memcpy(session.incoming_nonce.rawBytes, received->ap_nonce.rawBytes, sizeof(mit_nonce_t));

    /***** Send init response back *****/
    // Copy our nonce into response message
    mit_message_init_t * outgoing = (mit_message_init_t *)comp_plaintext;
    memcpy(outgoing->component_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    packet = (mit_packet_t *)transmit_buffer;
    set_ad(packet, COMPONENT_ID, MIT_CMD_INIT, sizeof(mit_message_init_t));
    memcpy(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    ret = mit_encrypt(packet, comp_plaintext, sizeof(mit_message_init_t));
    if (ret != SUCCESS_RETURN) {
        printf("encryption failed with error code %i\n", ret);
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    // TODO best place for this?
    increment_nonce(&session.outgoing_nonce);
    increment_nonce(&session.incoming_nonce);

    send_packet_and_ack(packet);
    return SUCCESS_RETURN;
}

/*********************************** MAIN *************************************/

int main(void) {
    // Enable Global Interrupts
    __enable_irq();

    // MIT: Initialize our custom features
    common_init();
    session_init();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    int len, ret;

    while (1) {
        // Wait for a packet
        len = wait_and_receive_packet(receive_buffer);

        // Special handling for scan commands
        if (len == sizeof(mit_comp_id_t)) {
            send_scan_and_ack(COMPONENT_ID);
            continue;
        }

        if (valid_session()) {
            // Normal command processing
            ret = component_process_cmd();
        } else {
            // Special handling while waiting for init
            ret = process_init_session();
        }

        // Send one-byte ack if command is invalid.
        if (ret != SUCCESS_RETURN) {
            send_ack();
        }
    }
}
