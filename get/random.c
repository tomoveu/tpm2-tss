/* This is example app tests ESAPI random
 *
 * <dimi@wolfssl.com>
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tss2_esys.h"
#include "esys_iutil.h"


int main(int argc, char argv[])
{
    TPM2_RC rc;
    ESYS_CONTEXT *esysContext;
    TPM2B_DIGEST *randomBytes;

    rc = Esys_Initialize(&esysContext, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize failed. Response Code : 0x%x", rc);
        goto exit;
    }
    printf("Esys Context initalized\n");

/*** Not needed
    rc = Esys_SetTimeout(esysContext, -1);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout failed. Response Code : 0x%x", rc);
        goto exit;
    }
    printf("Esys will work in synchronous mode\n");
***/

    rc = Esys_GetRandom(esysContext, ESYS_TR_NONE, ESYS_TR_NONE,
                        ESYS_TR_NONE, 24, &randomBytes);
    if (rc != TPM2_RC_SUCCESS) {
        printf("GetRandom FAILED! Response Code : 0x%x", rc);
        goto exit;
    }

    printf("Random: ");
    for(int i=0; i < randomBytes->size; i++) {
        printf("0x%2X ", randomBytes->buffer[i]);
    }
    printf("\n");

exit:

    Esys_Free(randomBytes);
    Esys_Finalize(&esysContext);

abort:

    return rc;
}
