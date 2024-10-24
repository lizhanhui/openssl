/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OPENSSL_TLCP_H
# define OPENSSL_TLCP_H
# pragma once

# include <openssl/opensslconf.h>
# include <openssl/prov_ssl.h>

# ifndef OPENSSL_NO_TLCP
#  ifdef  __cplusplus
extern "C" {
#  endif

/* TLCP version */
#  define TLCP1_1_VERSION_MAJOR 0x01
#  define TLCP1_1_VERSION_MINOR 0x01
#  define TLCP_VERSION          TLCP1_1_VERSION
#  define TLCP_VERSION_MAJOR    TLCP1_1_VERSION_MAJOR
#  define TLCP_VERSOIN_MINOR    TLCP1_1_VERSION_MINOR
/*
 * This tag is used to replace SSLv3 when use TLCP.
 * SSLv3 is not used default, so it always be the min protocal version in test,
 * but when add TLCP, the TLCP becomes the min version, and TLCP is commonly use,
 * then will cause some problems, so add this tag
 */
#  define MIN_VERSION_WITH_TLCP 0x0100

/* Compatible with GM/T 0024-2014 cipher suites name */
#  define TLCP_TXT_SM2DHE_WITH_SM4_SM3          "ECDHE-SM2-WITH-SM4-SM3"
#  define TLCP_TXT_SM2_WITH_SM4_SM3             "ECC-SM2-WITH-SM4-SM3"

/* GB/T 38636-2020 TLCP, cipher suites */
#  define TLCP_TXT_ECDHE_SM2_SM4_CBC_SM3        "ECDHE-SM2-SM4-CBC-SM3"
#  define TLCP_TXT_ECDHE_SM2_SM4_GCM_SM3        "ECDHE-SM2-SM4-GCM-SM3"
#  define TLCP_TXT_ECC_SM2_SM4_CBC_SM3          "ECC-SM2-SM4-CBC-SM3"
#  define TLCP_TXT_ECC_SM2_SM4_GCM_SM3          "ECC-SM2-SM4-GCM-SM3"
#  define TLCP_TXT_IBSDH_SM9_SM4_CBC_SM3        "IBSDH-SM9-SM4-CBC-SM3"
#  define TLCP_TXT_IBSDH_SM9_SM4_GCM_SM3        "IBSDH-SM9-SM4-GCM-SM3"
#  define TLCP_TXT_IBC_SM9_SM4_CBC_SM3          "IBC-SM9-SM4-CBC-SM3"
#  define TLCP_TXT_IBC_SM9_SM4_GCM_SM3          "IBC-SM9-SM4-GCM-SM3"
#  define TLCP_TXT_RSA_SM4_CBC_SM3              "RSA-SM4-CBC-SM3"
#  define TLCP_TXT_RSA_SM4_GCM_SM3              "RSA-SM4-GCM-SM3"
#  define TLCP_TXT_RSA_SM4_CBC_SHA256           "RSA-SM4-CBC-SHA256"
#  define TLCP_TXT_RSA_SM4_GCM_SHA256           "RSA-SM4-GCM-SHA256"

#  define TLCP_GB_ECDHE_SM2_SM4_CBC_SM3         "ECDHE_SM4_CBC_SM3"
#  define TLCP_GB_ECDHE_SM2_SM4_GCM_SM3         "ECDHE_SM4_GCM_SM3"
#  define TLCP_GB_ECC_SM2_SM4_CBC_SM3           "ECC_SM4_CBC_SM3"
#  define TLCP_GB_ECC_SM2_SM4_GCM_SM3           "ECC_SM4_GCM_SM3"
#  define TLCP_GB_IBSDH_SM9_SM4_CBC_SM3         "IBSDH_SM4_CBC_SM3"
#  define TLCP_GB_IBSDH_SM9_SM4_GCM_SM3         "IBSDH_SM4_GCM_SM3"
#  define TLCP_GB_IBC_SM9_SM4_CBC_SM3           "IBC_SM4_CBC_SM3"
#  define TLCP_GB_IBC_SM9_SM4_GCM_SM3           "IBC_SM4_GCM_SM3"
#  define TLCP_GB_RSA_SM4_CBC_SM3               "RSA_SM4_CBC_SM3"
#  define TLCP_GB_RSA_SM4_GCM_SM3               "RSA_SM4_GCM_SM3"
#  define TLCP_GB_RSA_SM4_CBC_SHA256            "RSA_SM4_CBC_SHA256"
#  define TLCP_GB_RSA_SM4_GCM_SHA256            "RSA_SM4_GCM_SHA256"

#  define TLCP_CK_ECDHE_SM2_SM4_CBC_SM3         0x0300E011
#  define TLCP_CK_ECDHE_SM2_SM4_GCM_SM3         0x0300E051
#  define TLCP_CK_ECC_SM2_SM4_CBC_SM3           0x0300E013
#  define TLCP_CK_ECC_SM2_SM4_GCM_SM3           0x0300E053
#  define TLCP_CK_IBSDH_SM9_SM4_CBC_SM3         0x0300E015
#  define TLCP_CK_IBSDH_SM9_SM4_GCM_SM3         0x0300E055
#  define TLCP_CK_IBC_SM9_SM4_CBC_SM3           0x0300E017
#  define TLCP_CK_IBC_SM9_SM4_GCM_SM3           0x0300E057
#  define TLCP_CK_RSA_SM4_CBC_SM3               0x0300E019
#  define TLCP_CK_RSA_SM4_GCM_SM3               0x0300E059
#  define TLCP_CK_RSA_SM4_CBC_SHA256            0x0300E01C
#  define TLCP_CK_RSA_SM4_GCM_SHA256            0x0300E05a


#  define TLCP_AD_UNSUPPORTED_SITE2SITE         200
#  define TLCP_AD_NO_AREA                       201
#  define TLCP_AD_UNSUPPORTED_AREATYPE          202
#  define TLCP_AD_BAD_IBCPARAM                  203
#  define TLCP_AD_UNSUPPORTED_IBCPARAM          204
#  define TLCP_AD_IDENTITY_NEED                 205

#  ifdef  __cplusplus
}
#  endif
# endif
#endif