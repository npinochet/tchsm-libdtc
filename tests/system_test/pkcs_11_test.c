/*
Copyright 2013 NIC Chile Research Labs.
This file is part of PKCS11-TsCrypto.

PKCS11-TsCrypto is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PKCS11-TsCrypto is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with PKCS11-TsCrypto.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// text has to freed by the user.
int read_all_file(FILE *fp, unsigned char **text) {
    int actual_max_buffer_size = 512;

    unsigned char *ret = malloc(actual_max_buffer_size * sizeof(*ret));
    int size = 0;

    int c;
    while ((c = getc (fp)) != EOF) {
        if (size + 1 > actual_max_buffer_size) {
            actual_max_buffer_size *= 2;
            ret = realloc(ret, actual_max_buffer_size * sizeof(*ret));
        }
        ret[size] = (unsigned char) c;
        size++;
    }
    ret = realloc(ret, size * sizeof(*ret));
    *text = ret;
    return size;
}

void
check_return_value(CK_RV rv, const char *message) {
    if (rv != CKR_OK) {
        fprintf(stderr, "Error at %s: %u\n",
                message, (unsigned int) rv);
        exit(EXIT_FAILURE);
    }
}

CK_RV
initialize() {
    return C_Initialize(NULL);
}

CK_SLOT_ID
get_slot() {
    CK_RV rv;
    CK_SLOT_ID slotId;
    CK_ULONG slotCount = 10;
    CK_SLOT_ID *slotIds = malloc(sizeof(CK_SLOT_ID) * slotCount);

    rv = C_GetSlotList(CK_TRUE, slotIds, &slotCount);
    check_return_value(rv, "get slot list");

    if (slotCount < 1) {
        fprintf(stderr, "Error; could not find any slots\n");
        exit(1);
    }

    slotId = slotIds[0];
    free(slotIds);
    printf("slot count: %d\n", (int) slotCount);
    return slotId;
}

CK_SESSION_HANDLE
start_session(CK_SLOT_ID slotId) {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    rv = C_OpenSession(slotId,
                       CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL,
                       NULL,
                       &session);
    check_return_value(rv, "open session");
    return session;
}

void
login(CK_SESSION_HANDLE session, CK_BYTE *pin) {
    CK_RV rv;
    if (pin) {
        rv = C_Login(session, CKU_USER, pin, strlen((char *) pin));
        check_return_value(rv, "log in");
    }
}

void
logout(CK_SESSION_HANDLE session) {
    CK_RV rv;
    rv = C_Logout(session);
    if (rv != CKR_USER_NOT_LOGGED_IN) {
        check_return_value(rv, "log out");
    }
}

void
end_session(CK_SESSION_HANDLE session) {
    CK_RV rv;
    rv = C_CloseSession(session);
    check_return_value(rv, "close session");
}

void
finalize() {
    C_Finalize(NULL);
}

void
show_key_info(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {
    CK_RV rv;
    CK_UTF8CHAR *label = (CK_UTF8CHAR *) malloc(80);
    CK_BYTE *id = (CK_BYTE *) malloc(10);
    size_t label_len;
    char *label_str;

    memset(id, 0, 10);

    CK_ATTRIBUTE template[] = {
            {CKA_LABEL, label, 80},
            {CKA_ID,    id,    1}
    };

    rv = C_GetAttributeValue(session, key, template, 2);
    check_return_value(rv, "get attribute value");

    fprintf(stdout, "Found a key:\n");
    label_len = template[0].ulValueLen;
    if (label_len > 0) {
        label_str = malloc(label_len + 1);
        memcpy(label_str, label, label_len);
        label_str[label_len] = '\0';
        fprintf(stdout, "\tKey label: %s\n", label_str);
        free(label_str);
    } else {
        fprintf(stdout, "\tKey label too large, or not found\n");
    }
    if (template[1].ulValueLen > 0) {
        fprintf(stdout, "\tKey ID: %02x\n", id[0]);
    } else {
        fprintf(stdout, "\tKey id too large, or not found\n");
    }

    free(label);
    free(id);
}

void
read_private_keys(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)}
    };
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;

    rv = C_FindObjectsInit(session, template, 1);
    check_return_value(rv, "Find objects init");

    rv = C_FindObjects(session, &object, 1, &objectCount);
    check_return_value(rv, "Find first object");

    while (objectCount > 0) {
        show_key_info(session, object);

        rv = C_FindObjects(session, &object, 1, &objectCount);
        check_return_value(rv, "Find other objects");
    }

    rv = C_FindObjectsFinal(session);
    check_return_value(rv, "Find objects final");
}

#define ID {0x45}
#define ID_LENGTH 1
#define LABEL "llave"
#define LABEL_LENGTH 5

void
create_key_pair(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_MECHANISM mechanism = {
            CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_ULONG modulusBits = 1024;
    CK_BYTE publicExponent[] = {1, 0, 1};
    CK_BYTE subject[] = LABEL;
    CK_BYTE id[] = ID;
    CK_BBOOL trueVal = CK_TRUE;
    CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_ID,              id,             sizeof(id)},
            {CKA_LABEL,           subject, LABEL_LENGTH},
            {CKA_TOKEN,           &trueVal,          sizeof(trueVal)},
            {CKA_ENCRYPT,         &trueVal,          sizeof(trueVal)},
            {CKA_VERIFY,          &trueVal,          sizeof(trueVal)},
            {CKA_WRAP,            &trueVal,          sizeof(trueVal)},
            {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
            {CKA_PUBLIC_EXPONENT, publicExponent, 3}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
            {CKA_ID,        id,    sizeof(id)},
            {CKA_LABEL,     subject, LABEL_LENGTH},
            {CKA_TOKEN,     &trueVal, sizeof(trueVal)},
            {CKA_PRIVATE,   &trueVal, sizeof(trueVal)},
            {CKA_SENSITIVE, &trueVal, sizeof(trueVal)},
            {CKA_DECRYPT,   &trueVal, sizeof(trueVal)},
            {CKA_SIGN,      &trueVal, sizeof(trueVal)},
            {CKA_UNWRAP,    &trueVal, sizeof(trueVal)}
    };

    rv = C_GenerateKeyPair(session,
                           &mechanism,
                           publicKeyTemplate, 8,
                           privateKeyTemplate, 8,
                           &publicKey,
                           &privateKey);
    check_return_value(rv, "generate key pair");
}

CK_OBJECT_HANDLE
get_private_key(CK_SESSION_HANDLE session, CK_BYTE *id, size_t id_len) {
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_ID,    id,        id_len}
    };
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;

    rv = C_FindObjectsInit(session, template, 1);
    check_return_value(rv, "Find objects init");

    rv = C_FindObjects(session, &object, 1, &objectCount);
    check_return_value(rv, "Find first object");

    if (objectCount > 0) {
        rv = C_FindObjectsFinal(session);
        check_return_value(rv, "Find objects final");
        return object;
    } else {
        fprintf(stderr, "Private key not found\n");
        exit(2);
    }
}

CK_OBJECT_HANDLE
get_public_key(CK_SESSION_HANDLE session, CK_BYTE *id, size_t id_len) {
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE template[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_ID,    id,        id_len}
    };
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;

    rv = C_FindObjectsInit(session, template, 1);
    check_return_value(rv, "Find objects init");

    rv = C_FindObjects(session, &object, 1, &objectCount);
    check_return_value(rv, "Find first object");

    if (objectCount > 0) {
        rv = C_FindObjectsFinal(session);
        check_return_value(rv, "Find objects final");
        return object;
    } else {
        fprintf(stderr, "Public key not found\n");
        exit(3);
    }
}

CK_BYTE_PTR
sign_data(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen, CK_ULONG_PTR size) {
    CK_RV rv;
    CK_BYTE id[] = ID;
    CK_OBJECT_HANDLE key = get_private_key(session, id, sizeof(id));
    CK_MECHANISM sign_mechanism;

    CK_ULONG signatureLen = 1024;
    CK_BYTE *signature = malloc(signatureLen);

    sign_mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
    sign_mechanism.pParameter = NULL;
    sign_mechanism.ulParameterLen = 0;

    rv = C_SignInit(session, &sign_mechanism, key);
    check_return_value(rv, "sign init new");

    rv = C_Sign(session, data, dataLen, signature, &signatureLen);
    check_return_value(rv, "sign final");

    *size = signatureLen;
    return signature;
}

void
verify_data(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen, CK_BYTE_PTR signature, CK_ULONG signatureLen) {
    CK_RV rv;
    CK_BYTE id[] = ID;
    CK_OBJECT_HANDLE key = get_public_key(session, id, sizeof(id));
    CK_MECHANISM sign_mechanism;

    sign_mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
    sign_mechanism.pParameter = NULL;
    sign_mechanism.ulParameterLen = 0;

    rv = C_VerifyInit(session, &sign_mechanism, key);
    check_return_value(rv, "verify init new");

    rv = C_Verify(session, data, dataLen, signature, signatureLen);
    check_return_value(rv, "verify final");
}


int
main(int argc, char **argv) {
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE session;
    FILE *input_file = NULL;
    FILE *output_file = NULL;

    char *howManyValue = NULL;
    char *filename = NULL;
    CK_BYTE_PTR pinValue = NULL;
    int createKeys = 0;
    int howMany = 1;

    int c;
    int pinLen;
    while ((c = getopt(argc, argv, "cn:p:f:")) != -1) {
        switch (c) {
            case 'c':
                createKeys = 1;
                break;
            case 'n':
                howManyValue = optarg;
                howMany = atoi(howManyValue);
                break;
            case 'f':
                filename = strdup(optarg);
                break;
            case 'p':
                pinLen = strlen(optarg);
                pinValue = memcpy(malloc(pinLen + 1), optarg, pinLen);
                pinValue[pinLen] = '\0';
                break;
            default:
                abort();
        }
    }

    initialize();
    slot = get_slot();
    
    session = start_session(slot);
    if (pinValue) {
	login(session, pinValue);
    }

    read_private_keys(session);

    if (createKeys) {
	create_key_pair(session);
    }

    /* signing */
    if (filename) {
	input_file = fopen(filename, "r");
	output_file = stdout;
	CK_BYTE_PTR text;
	CK_ULONG text_size = read_all_file(input_file, &text);
	int i;
	for (i = 0; i < howMany; i++) {
	    CK_ULONG signatureLen;
	    CK_BYTE_PTR signature = sign_data(session, text, text_size, &signatureLen);
	    verify_data(session, text, text_size, signature, signatureLen);
	}

	fclose(input_file);
	fclose(output_file);
    }

    if (pinValue) {
	logout(session);
    }
    end_session(session);

    finalize();

    return EXIT_SUCCESS;
}

