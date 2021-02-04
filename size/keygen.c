/* This is example app uses the ESAPI interface
 * of the Intel/Infineon TSS2 stack to perform
 * three of the most common TPM operations:
 * Create Primary Key under the owner Hierarchy,
 * Create Signing Key under a Primary Key,
 * Load the Signing Key for use. And unloading all.
 *
 * <dimi@wolfssl.com>
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tss2_esys.h"
#include "esys_iutil.h"

static const TPM2B_AUTH gStorageKeyAuth = {
    .size = 22,
    .buffer = {'T','h','i','s','I','s','M','y',
               'S','t','o','r','a','g','e',
               'K','e','y','A','u','t','h'}
};

static const TPM2B_AUTH gKeyAuth = {
    .size = 15,
    .buffer = {'T','h','i','s','I','s','M','y',
               'K','e','y','A','u','t','h'}
};

int main(int argc, char argv[])
{
    TPM2_RC rc;
    ESYS_CONTEXT *esysContext;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR loadedKeyHandle = ESYS_TR_NONE;
    /* Primary Key */
    TPM2B_PUBLIC inPublic;
    TPM2B_PUBLIC *outPublicPrimary = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_SENSITIVE_CREATE inSensitivePrimary;
    /* Singing Key */
    TPM2B_PUBLIC inPublicSignKey;
    TPM2B_PUBLIC *outPublicSignKey = NULL;
    TPM2B_PRIVATE *outPrivateSignKey = NULL;
    TPM2B_CREATION_DATA *creationDataSignKey = NULL;
    TPM2B_DIGEST *creationHashSignKey = NULL;
    TPMT_TK_CREATION *creationTicketSignKey = NULL;
    TPM2B_SENSITIVE_CREATE inSensitiveSignKey;
    /* ESYS related */
    RSRC_NODE_T *primaryHandle_node = NULL;
    /* Common strucutres */
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };


    rc = Esys_Initialize(&esysContext, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize failed. Response Code : 0x%x", rc);
        goto abort;
    }
    printf("Esys Context initalized\n");

    outsideInfo.size = 0;
    creationPCR.count = 0;

    /* Prepare auths for Storage key */
    inSensitivePrimary.size = 0;
    inSensitivePrimary.sensitive.userAuth.size = 0;
    inSensitivePrimary.sensitive.data.size = 0;
    inSensitivePrimary.sensitive.userAuth = gStorageKeyAuth;
    /* Prepare auths for Signing key */
    inSensitiveSignKey.size = 0;
    inSensitiveSignKey.sensitive.userAuth.size = 0;
    inSensitiveSignKey.sensitive.data.size = 0;
    inSensitiveSignKey.sensitive.userAuth = gKeyAuth;

    /*** Prepare for Storage Key ***/
    inPublic.size = 0;
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN);
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES,
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    /* Creating Storage Key under Owner Hierarchy */
    rc = Esys_TR_SetAuth(esysContext, ESYS_TR_RH_OWNER, &authValue);
    if (rc != TSS2_RC_SUCCESS) {
        printf("SetAuth failed for Hierarchy\n");
        goto exit;
    }

    rc = Esys_CreatePrimary(esysContext, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
                &outsideInfo, &creationPCR, &primaryHandle, &outPublicPrimary,
                &creationData, &creationHash, &creationTicket);
    if (rc != 0) {
        printf("CreatePrimary failed\n");
        goto exit;
    }

    rc = esys_GetResourceObject(esysContext, primaryHandle, &primaryHandle_node);
    if (rc != 0) {
        printf("Extract primary handled from ESYS object failed\n");
        goto exit;
    }
    printf("Storage Key created successfully\n");

    /*** Prepare for Signing Key ***/
    inPublic.size = 0;
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN);
    inPublic.publicArea.authPolicy.size = 0;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES,
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
    inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.publicArea.unique.rsa.size = 0;

    /* Creating Signing Key under Storage Key */

    rc = Esys_Create(esysContext, primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    &inSensitiveSignKey,
                    &inPublic,
                    &outsideInfo,
                    &creationPCR,
                    &outPrivateSignKey,
                    &outPublicSignKey,
                    &creationData, &creationHash, &creationTicket);
    if (rc != 0) {
        printf("Create signing key failed\n");
        goto exit_flush_primary;
    }
    printf("Singing Key created successfully\n");

    rc = Esys_Load(esysContext, primaryHandle,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                    outPrivateSignKey, outPublicSignKey,
                    &loadedKeyHandle);
    if (rc != 0) {
        printf("Loading the signing key failed\n");
        goto exit_flush_primary;
    }
    printf("Signing Key Loaded\n");

exit_flush_all:

    Esys_FlushContext(esysContext, loadedKeyHandle);
    printf("Storage Key flushed\n");

exit_flush_primary:

    Esys_FlushContext(esysContext, primaryHandle);
    printf("Signing Key flushed\n");

exit:

    Esys_Free(outPublicPrimary);
    Esys_Free(outPrivateSignKey);
    Esys_Free(outPublicSignKey);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Finalize(&esysContext);

abort:

    return rc;
}
