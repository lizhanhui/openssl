/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <crypto/sm4.h>
#include "prov/ciphercommon.h"
#include "prov/ciphercommon_gcm.h"

typedef struct prov_sm4_gcm_ctx_st {
    PROV_GCM_CTX base;          /* must be first entry in struct */
    union {
        OSSL_UNION_ALIGN;
        SM4_KEY ks;
    } ks;                       /* SM4 key schedule to use */
} PROV_SM4_GCM_CTX;

const PROV_GCM_HW *ossl_prov_sm4_hw_gcm(size_t keybits);