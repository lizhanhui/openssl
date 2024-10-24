/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*****************************************************************************
 *                                                                           *
 * These enums should be considered PRIVATE to the state machine. No         *
 * non-state machine code should need to use these                           *
 *                                                                           *
 *****************************************************************************/
/*
 * Valid return codes used for functions performing work prior to or after
 * sending or receiving a message
 */

typedef enum {
    /* Something went wrong */
    WORK_ERROR_TLCP,
    /* We're done working and there shouldn't be anything else to do after */
    WORK_FINISHED_STOP_TLCP,
    /* We're done working move onto the next thing */
    WORK_FINISHED_CONTINUE_TLCP,
    /* We're working on phase A */
    WORK_MORE_A_TLCP,
    /* We're working on phase B */
    WORK_MORE_B_TLCP,
    /* We're working on phase C */
    WORK_MORE_C_TLCP
} WORK_STATE_TLCP;

/* Write transition return codes */
typedef enum {
    /* Something went wrong */
    WRITE_TRAN_ERROR_TLCP,
    /* A transition was successfully completed and we should continue */
    WRITE_TRAN_CONTINUE_TLCP,
    /* There is no more write work to be done */
    WRITE_TRAN_FINISHED_TLCP
} WRITE_TRAN_TLCP;

/* Message flow states */
typedef enum {
    /* No handshake in progress */
    MSG_FLOW_UNINITED_TLCP,
    /* A permanent error with this connection */
    MSG_FLOW_ERROR_TLCP,
    /* We are reading messages */
    MSG_FLOW_READING_TLCP,
    /* We are writing messages */
    MSG_FLOW_WRITING_TLCP,
    /* Handshake has finished */
    MSG_FLOW_FINISHED_TLCP
} MSG_FLOW_STATE_TLCP;

/* Read states */
typedef enum {
    READ_STATE_HEADER_TLCP,
    READ_STATE_BODY_TLCP,
    READ_STATE_POST_PROCESS_TLCP
} READ_STATE_TLCP;

/* Write states */
typedef enum {
    WRITE_STATE_TRANSITION_TLCP,
    WRITE_STATE_PRE_WORK_TLCP,
    WRITE_STATE_SEND_TLCP,
    WRITE_STATE_POST_WORK_TLCP
} WRITE_STATE_TLCP;

typedef enum {
    /* The enc_write_ctx can be used normally */
    ENC_WRITE_STATE_VALID_TLCP,
    /* The enc_write_ctx cannot be used */
    ENC_WRITE_STATE_INVALID_TLCP,
    /* Write alerts in plaintext, but otherwise use the enc_write_ctx */
    ENC_WRITE_STATE_WRITE_PLAIN_ALERTS_TLCP
} ENC_WRITE_STATES_TLCP;

typedef enum {
    /* The enc_read_ctx can be used normally */
    ENC_READ_STATE_VALID_TLCP,
    /* We may receive encrypted or plaintext alerts */
    ENC_READ_STATE_ALLOW_PLAIN_ALERTS_TLCP
} ENC_READ_STATES_TLCP;

/*****************************************************************************
 *                                                                           *
 * This structure should be considered "opaque" to anything outside of the   *
 * state machine. No non-state machine code should be accessing the members  *
 * of this structure.                                                        *
 *                                                                           *
 *****************************************************************************/

struct ossl_statem_st_tlcp {
    MSG_FLOW_STATE_TLCP state;
    WRITE_STATE_TLCP write_state;
    WORK_STATE_TLCP write_state_work;
    READ_STATE_TLCP read_state;
    WORK_STATE_TLCP read_state_work;
    OSSL_HANDSHAKE_STATE hand_state;
    /* The handshake state requested by an API call (e.g. HelloRequest) */
    OSSL_HANDSHAKE_STATE request_state;
    int in_init;
    int read_state_first_init;
    /* true when we are actually in SSL_accept() or SSL_connect() */
    int in_handshake;
    /*
     * True when are processing a "real" handshake that needs cleaning up (not
     * just a HelloRequest or similar).
     */
    int cleanuphand;
    /* Should we skip the CertificateVerify message? */
    unsigned int no_cert_verify;
    int use_timer;
    ENC_WRITE_STATES_TLCP enc_write_state;
    ENC_READ_STATES_TLCP enc_read_state;
};
typedef struct ossl_statem_st_tlcp OSSL_STATEM_TLCP;

/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * state machine. Any libssl code may call these functions/macros            *
 *                                                                           *
 *****************************************************************************/

__owur int ossl_statem_accept_tlcp(SSL *s);
__owur int ossl_statem_connect_tlcp(SSL *s);
void ossl_statem_clear_tlcp(SSL *s);
void ossl_statem_set_renegotiate_tlcp(SSL *s);
void ossl_statem_send_fatal_tlcp(SSL *s, int al);
void ossl_statem_fatal_tlcp(SSL *s, int al, int reason, const char *fmt, ...);
# define SSL_AD_NO_ALERT    -1
# define SSLfatal_alert_tlcp(s, al) ossl_statem_send_fatal_tlcp((s), (al))
# define SSLfatal_tlcp(s, al, r) SSLfatal_data_tlcp((s), (al), (r), NULL)
# define SSLfatal_data_tlcp                                     \
    (ERR_new(),                                                 \
     ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC),   \
     ossl_statem_fatal_tlcp)

int ossl_statem_in_error_tlcp(const SSL *s);
void ossl_statem_set_in_init_tlcp(SSL *s, int init);
int ossl_statem_get_in_handshake_tlcp(SSL *s);
void ossl_statem_set_in_handshake_tlcp(SSL *s, int inhand);
__owur int ossl_statem_skip_early_data_tlcp(SSL *s);
void ossl_statem_check_finish_init_tlcp(SSL *s, int send);
void ossl_statem_set_hello_verify_done_tlcp(SSL *s);
__owur int ossl_statem_app_data_allowed_tlcp(SSL *s);
__owur int ossl_statem_export_allowed_tlcp(SSL *s);
__owur int ossl_statem_export_early_allowed_tlcp(SSL *s);

/* Flush the write BIO */
int statem_flush_tlcp(SSL *s);
int state_machine_tlcp(SSL *s, int server);
int SSL_connection_is_tlcp(SSL *s, int is_server);