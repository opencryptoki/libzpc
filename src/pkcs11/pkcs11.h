// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#ifndef PKCS11_H
#define PKCS11_H

#ifdef __cplusplus
extern "C" {
#endif

// The defines in this header file are derived from
// https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/include/pkcs11-v3.2/pkcs11.h

#define CK_TRUE  1
#define CK_FALSE 0

#define CK_PTR *

#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int CK_LONG;
typedef CK_ULONG CK_FLAGS;

#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0

typedef CK_BYTE CK_PTR CK_BYTE_PTR;
typedef CK_CHAR CK_PTR CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR CK_UTF8CHAR_PTR;
typedef CK_ULONG CK_PTR CK_ULONG_PTR;
typedef void CK_PTR CK_VOID_PTR;
typedef CK_ULONG CK_PTR CK_FLAGS_PTR;
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;

#define CK_INVALID_HANDLE 0

typedef struct CK_VERSION {
	CK_BYTE major;
	CK_BYTE minor;
} CK_VERSION;

typedef CK_VERSION CK_PTR CK_VERSION_PTR;

typedef struct CK_INFO {
	CK_VERSION cryptokiVersion;
	CK_CHAR manufacturerID[32];
	CK_FLAGS flags;
	CK_CHAR libraryDescription[32];
	CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO CK_PTR CK_INFO_PTR;

typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER 0

typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;

typedef struct CK_SLOT_INFO {
	CK_CHAR slotDescription[64];
	CK_CHAR manufacturerID[32];
	CK_FLAGS flags;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

#define CKF_TOKEN_PRESENT	0x00000001
#define CKF_REMOVABLE_DEVICE	0x00000002
#define CKF_HW_SLOT		0x00000004

typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
	CK_CHAR label[32];
	CK_CHAR manufacturerID[32];
	CK_CHAR model[16];
	CK_CHAR serialNumber[16];
	CK_FLAGS flags;
	CK_ULONG ulMaxSessionCount;
	CK_ULONG ulSessionCount;
	CK_ULONG ulMaxRwSessionCount;
	CK_ULONG ulRwSessionCount;
	CK_ULONG ulMaxPinLen;
	CK_ULONG ulMinPinLen;
	CK_ULONG ulTotalPublicMemory;
	CK_ULONG ulFreePublicMemory;
	CK_ULONG ulTotalPrivateMemory;
	CK_ULONG ulFreePrivateMemory;
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
	CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

#define CKF_RNG					0x00000001
#define CKF_WRITE_PROTECTED			0x00000002
#define CKF_LOGIN_REQUIRED			0x00000004
#define CKF_USER_PIN_INITIALIZED		0x00000008
#define CKF_RESTORE_KEY_NOT_NEEDED		0x00000020
#define CKF_CLOCK_ON_TOKEN			0x00000040
#define CKF_PROTECTED_AUTHENTICATION_PATH	0x00000100
#define CKF_DUAL_CRYPTO_OPERATIONS		0x00000200
#define CKF_TOKEN_INITIALIZED			0x00000400
#define CKF_SECONDARY_AUTHENTICATION		0x00000800
#define CKF_USER_PIN_COUNT_LOW			0x00010000
#define CKF_USER_PIN_FINAL_TRY			0x00020000
#define CKF_USER_PIN_LOCKED			0x00040000
#define CKF_USER_PIN_TO_BE_CHANGED		0x00080000
#define CKF_SO_PIN_COUNT_LOW			0x00100000
#define CKF_SO_PIN_FINAL_TRY			0x00200000
#define CKF_SO_PIN_LOCKED			0x00400000
#define CKF_SO_PIN_TO_BE_CHANGED		0x00800000
#define CKF_ERROR_STATE				0x01000000
#define CKF_SEED_RANDOM_REQUIRED		0x02000000
#define CKF_ASYNC_SESSION_SUPPORTED		0x04000000

typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;

typedef CK_ULONG CK_USER_TYPE;
#define CKU_SO			0
#define CKU_USER		1
#define CKU_CONTEXT_SPECIFIC	2

typedef CK_ULONG CK_STATE;
#define CKS_RO_PUBLIC_SESSION	0
#define CKS_RO_USER_FUNCTIONS	1
#define CKS_RW_PUBLIC_SESSION	2
#define CKS_RW_USER_FUNCTIONS	3
#define CKS_RW_SO_FUNCTIONS	4

typedef struct CK_SESSION_INFO {
	CK_SLOT_ID slotID;
	CK_STATE state;
	CK_FLAGS flags;
	CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

#define CKF_RW_SESSION 		0x00000002
#define CKF_SERIAL_SESSION	0x00000004
#define CKF_ASYNC_SESSION	0x00000008

typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;

typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;

typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_OBJECT_CLASS CK_PTR CK_OBJECT_CLASS_PTR;

#define CKO_DATA		0x00000000
#define CKO_CERTIFICATE		0x00000001
#define CKO_PUBLIC_KEY		0x00000002
#define CKO_PRIVATE_KEY		0x00000003
#define CKO_SECRET_KEY		0x00000004
#define CKO_HW_FEATURE		0x00000005
#define CKO_DOMAIN_PARAMETERS	0x00000006
#define CKO_PROFILE		0x00000009
#define CKO_VALIDATION		0x0000000A
#define CKO_TRUST		0x0000000B
#define CKO_VENDOR_DEFINED	0x80000000

typedef CK_ULONG CK_KEY_TYPE;

#define CKK_RSA			0x00000000
#define CKK_DSA			0x00000001
#define CKK_DH			0x00000002
#define CKK_EC			0x00000003
#define CKK_GENERIC_SECRET	0x00000010
#define CKK_AES			0x0000001F
#define CKK_AES_XTS 		0x00000035
#define CKK_EC_EDWARDS		0x00000040
#define CKK_EC_MONTGOMERY	0x00000041

typedef CK_ULONG CK_ATTRIBUTE_TYPE;

#define CKF_ARRAY_ATTRIBUTE	0x40000000

#define CKA_CLASS		0x00000000
#define CKA_TOKEN		0x00000001
#define CKA_PRIVATE		0x00000002
#define CKA_LABEL		0x00000003
#define CKA_UNIQUE_ID		0x00000004
#define CKA_APPLICATION		0x00000010
#define CKA_VALUE		0x00000011
#define CKA_OBJECT_ID		0x00000012
#define CKA_CERTIFICATE_TYP	0x00000080
#define CKA_ISSUER		0x00000081
#define CKA_SERIAL_NUMBER	0x00000082
#define CKA_AC_ISSUER		0x00000083
#define CKA_OWNER		0x00000084
#define CKA_ATTR_TYPES		0x00000085
#define CKA_TRUSTED		0x00000086
#define CKA_KEY_TYPE		0x00000100
#define CKA_SUBJECT		0x00000101
#define CKA_ID			0x00000102
#define CKA_SENSITIVE		0x00000103
#define CKA_ENCRYPT		0x00000104
#define CKA_DECRYPT		0x00000105
#define CKA_WRAP		0x00000106
#define CKA_UNWRAP		0x00000107
#define CKA_SIGN		0x00000108
#define CKA_SIGN_RECOVER	0x00000109
#define CKA_VERIFY		0x0000010A
#define CKA_VERIFY_RECOVER	0x0000010B
#define CKA_DERIVE		0x0000010C
#define CKA_START_DATE		0x00000110
#define CKA_END_DATE		0x00000111
#define CKA_PUBLIC_KEY_INFO	0x00000129
#define CKA_VALUE_BITS		0x00000160
#define CKA_VALUE_LEN		0x00000161
#define CKA_EXTRACTABLE		0x00000162
#define CKA_LOCAL		0x00000163
#define CKA_NEVER_EXTRACTABLE	0x00000164
#define CKA_ALWAYS_SENSITIVE	0x00000165
#define CKA_MODIFIABLE		0x00000170
#define CKA_COPYABLE		0x00000171
#define CKA_DESTROYABLE		0x00000172
#define CKA_EC_PARAMS		0x00000180
#define CKA_EC_POINT		0x00000181
#define CKA_ALWAYS_AUTHENTICATE	0x00000202
#define CKA_WRAP_WITH_TRUSTED	0x00000210
#define CKA_ENCAPSULATE		0x00000633
#define CKA_DECAPSULATE		0x00000634

#define CKA_WRAP_TEMPLATE	(CKF_ARRAY_ATTRIBUTE | 0x00000211)
#define CKA_UNWRAP_TEMPLATE	(CKF_ARRAY_ATTRIBUTE | 0x00000212)
#define CKA_DERIVE_TEMPLATE	(CKF_ARRAY_ATTRIBUTE | 0x00000213)

typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

typedef struct CK_DATE {
	CK_CHAR year[4];
	CK_CHAR month[2];
	CK_CHAR day[2];
} CK_DATE;

typedef CK_ULONG CK_MECHANISM_TYPE;

#define CKM_ECDSA 			0x00001041
#define CKM_ECDSA_SHA1			0x00001042
#define CKM_ECDSA_SHA224		0x00001043
#define CKM_ECDSA_SHA256		0x00001044
#define CKM_ECDSA_SHA384		0x00001045
#define CKM_ECDSA_SHA512		0x00001046
#define CKM_ECDSA_SHA3_224		0x00001047
#define CKM_ECDSA_SHA3_256		0x00001048
#define CKM_ECDSA_SHA3_384		0x00001049
#define CKM_ECDSA_SHA3_512		0x0000104A
#define CKM_AES_XTS			0x00001071
#define CKM_AES_ECB			0x00001081
#define CKM_AES_CBC			0x00001082
#define CKM_AES_CTR			0x00001086
#define CKM_AES_GCM			0x00001087
#define CKM_EDDSA			0x00001057

typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;

typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
	CK_ULONG ulMinKeySize;
	CK_ULONG ulMaxKeySize;
	CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;

#define CKF_HW			0x00000001
#define CKF_MESSAGE_ENCRYPT	0x00000002
#define CKF_MESSAGE_DECRYPT	0x00000004
#define CKF_MESSAGE_SIGN	0x00000008
#define CKF_MESSAGE_VERIFY	0x00000010
#define CKF_MULTI_MESSAGE	0x00000020
#define CKF_FIND_OBJECTS	0x00000040
#define CKF_ENCRYPT		0x00000100
#define CKF_DECRYPT		0x00000200
#define CKF_DIGEST		0x00000400
#define CKF_SIGN		0x00000800
#define CKF_SIGN_RECOVER	0x00001000
#define CKF_VERIFY		0x00002000
#define CKF_VERIFY_RECOVER	0x00004000
#define CKF_GENERATE		0x00008000
#define CKF_GENERATE_KEY_PAIR	0x00010000
#define CKF_WRAP		0x00020000
#define CKF_UNWRAP		0x00040000
#define CKF_DERIVE		0x00080000
#define CKF_EC_F_P		0x00100000
#define CKF_EC_F_2M		0x00200000
#define CKF_EC_ECPARAMETERS	0x00400000
#define CKF_EC_OID		0x00800000
#define CKF_EC_UNCOMPRESS	0x01000000
#define CKF_EC_COMPRESS		0x02000000
#define CKF_EC_CURVENAME	0x04000000
#define CKF_ENCAPSULATE		0x10000000
#define CKF_DECAPSULATE		0x20000000

typedef CK_ULONG CK_RV;

#define CKR_OK					0x00000000
#define CKR_CANCEL				0x00000001
#define CKR_HOST_MEMORY				0x00000002
#define CKR_SLOT_ID_INVALID			0x00000003
#define CKR_GENERAL_ERROR			0x00000005
#define CKR_FUNCTION_FAILED			0x00000006
#define CKR_ARGUMENTS_BAD			0x00000007
#define CKR_NO_EVENT				0x00000008
#define CKR_NEED_TO_CREATE_THREADS		0x00000009
#define CKR_CANT_LOCK				0x0000000A
#define CKR_ATTRIBUTE_READ_ONLY			0x00000010
#define CKR_ATTRIBUTE_SENSITIVE			0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID		0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID		0x00000013
#define CKR_ACTION_PROHIBITED			0x0000001B
#define CKR_DATA_INVALID			0x00000020
#define CKR_DATA_LEN_RANGE			0x00000021
#define CKR_DEVICE_ERROR			0x00000030
#define CKR_DEVICE_MEMORY			0x00000031
#define CKR_DEVICE_REMOVED			0x00000032
#define CKR_ENCRYPTED_DATA_INVALID		0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE		0x00000041
#define CKR_AEAD_DECRYPT_FAILED			0x00000042
#define CKR_FUNCTION_CANCELED			0x00000050
#define CKR_FUNCTION_NOT_PARALLEL		0x00000051
#define CKR_FUNCTION_NOT_SUPPORTED		0x00000054
#define CKR_KEY_HANDLE_INVALID			0x00000060
#define CKR_KEY_SIZE_RANGE			0x00000062
#define CKR_KEY_TYPE_INCONSISTENT		0x00000063
#define CKR_KEY_NOT_NEEDED			0x00000064
#define CKR_KEY_CHANGED				0x00000065
#define CKR_KEY_NEEDED				0x00000066
#define CKR_KEY_INDIGESTIBLE			0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED		0x00000068
#define CKR_KEY_NOT_WRAPPABLE			0x00000069
#define CKR_KEY_UNEXTRACTABLE			0x0000006A
#define CKR_MECHANISM_INVALID			0x00000070
#define CKR_MECHANISM_PARAM_INVALID		0x00000071
#define CKR_OBJECT_HANDLE_INVALID		0x00000082
#define CKR_OPERATION_ACTIVE			0x00000090
#define CKR_OPERATION_NOT_INITIALIZED		0x00000091
#define CKR_PIN_INCORRECT			0x000000A0
#define CKR_PIN_INVALID				0x000000A1
#define CKR_PIN_LEN_RANGE			0x000000A2
#define CKR_PIN_EXPIRED				0x000000A3
#define CKR_PIN_LOCKED				0x000000A4
#define CKR_SESSION_CLOSED			0x000000B0
#define CKR_SESSION_COUNT			0x000000B1
#define CKR_SESSION_HANDLE_INVALID		0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED	0x000000B4
#define CKR_SESSION_READ_ONLY			0x000000B5
#define CKR_SESSION_EXISTS			0x000000B6
#define CKR_SESSION_READ_ONLY_EXISTS		0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS	0x000000B8
#define CKR_SIGNATURE_INVALID			0x000000C0
#define CKR_SIGNATURE_LEN_RANGE			0x000000C1
#define CKR_TEMPLATE_INCOMPLETE			0x000000D0
#define CKR_TEMPLATE_INCONSISTENT		0x000000D1
#define CKR_TOKEN_NOT_PRESENT			0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED		0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED		0x000000E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID	0x000000F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE		0x000000F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT	0x000000F2
#define CKR_USER_ALREADY_LOGGED_IN		0x00000100
#define CKR_USER_NOT_LOGGED_IN			0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED		0x00000102
#define CKR_USER_TYPE_INVALID			0x00000103
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN	0x00000104
#define CKR_USER_TOO_MANY_TYPES			0x00000105
#define CKR_WRAPPED_KEY_INVALID			0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE		0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID		0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE		0x00000114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT	0x00000115
#define CKR_RANDOM_SEED_NOT_SUPPORTED		0x00000120
#define CKR_RANDOM_NO_RNG			0x00000121
#define CKR_DOMAIN_PARAMS_INVALID		0x00000130
#define CKR_CURVE_NOT_SUPPORTED			0x00000140
#define CKR_BUFFER_TOO_SMALL			0x00000150
#define CKR_SAVED_STATE_INVALID			0x00000160
#define CKR_INFORMATION_SENSITIVE		0x00000170
#define CKR_STATE_UNSAVEABLE			0x00000180
#define CKR_CRYPTOKI_NOT_INITIALIZED		0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED	0x00000191
#define CKR_MUTEX_BAD				0x000001A0
#define CKR_MUTEX_NOT_LOCKED			0x000001A1
#define CKR_NEW_PIN_MODE			0x000001B0
#define CKR_NEXT_OTP				0x000001B1
#define CKR_EXCEEDED_MAX_ITERATIONS		0x000001B5
#define CKR_FIPS_SELF_TEST_FAILED		0x000001B6
#define CKR_LIBRARY_LOAD_FAILED			0x000001B7
#define CKR_PIN_TOO_WEAK			0x000001B8
#define CKR_PUBLIC_KEY_INVALID			0x000001B9
#define CKR_FUNCTION_REJECTED			0x00000200
#define CKR_TOKEN_RESOURCE_EXCEEDED		0x00000201
#define CKR_OPERATION_CANCEL_FAILED		0x00000202
#define CKR_KEY_EXHAUSTED			0x00000203
#define CKR_PENDING				0x00000204
#define CKR_SESSION_ASYNC_NOT_SUPPORTED		0x00000205
#define CKR_SEED_RANDOM_REQUIRED		0x00000206
#define CKR_OPERATION_NOT_VALIDATED		0x00000207
#define CKR_TOKEN_NOT_INITIALIZED		0x00000208
#define CKR_PARAMETER_SET_NOT_SUPPORTED		0x00000209

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
		CK_SESSION_HANDLE hSession,
		CK_NOTIFICATION event,
		CK_VOID_PTR pApplication
	);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
		CK_VOID_PTR_PTR ppMutex
	);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
		CK_VOID_PTR pMutex
	);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
		CK_VOID_PTR pMutex
	);

typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
		CK_VOID_PTR pMutex
	);

typedef struct CK_C_INITIALIZE_ARGS {
	CK_CREATEMUTEX CreateMutex;
	CK_DESTROYMUTEX DestroyMutex;
	CK_LOCKMUTEX LockMutex;
	CK_UNLOCKMUTEX UnlockMutex;
	CK_FLAGS flags;
	CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS	0x00000001
#define CKF_OS_LOCKING_OK			0x00000002

typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;

typedef struct CK_AES_CTR_PARAMS {
	CK_ULONG ulCounterBits;
	CK_BYTE cb[16];
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS CK_PTR CK_AES_CTR_PARAMS_PTR;

typedef struct CK_GCM_PARAMS {
	CK_BYTE_PTR pIv;
	CK_ULONG ulIvLen;
	CK_ULONG ulIvBits;
	CK_BYTE_PTR pAAD;
	CK_ULONG ulAADLen;
	CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

typedef CK_GCM_PARAMS CK_PTR CK_GCM_PARAMS_PTR;

typedef struct CK_EDDSA_PARAMS {
	CK_BBOOL            phFlag;
	CK_ULONG            ulContextDataLen;
	CK_BYTE_PTR         pContextData;
} CK_EDDSA_PARAMS;

typedef CK_EDDSA_PARAMS CK_PTR CK_EDDSA_PARAMS_PTR;

typedef struct CK_ASYNC_DATA {
	CK_ULONG            ulVersion;
	CK_BYTE_PTR         pValue;
	CK_ULONG            ulValue;
	CK_OBJECT_HANDLE    hObject;
	CK_OBJECT_HANDLE    hAdditionalObject;
} CK_ASYNC_DATA;

typedef CK_ASYNC_DATA CK_PTR CK_ASYNC_DATA_PTR;

typedef CK_ULONG CK_SESSION_VALIDATION_FLAGS_TYPE;

#define CKF_INTERFACE_FORK_SAFE		0x00000001UL

typedef struct CK_INTERFACE {
	CK_UTF8CHAR_PTR pInterfaceName;
	CK_VOID_PTR pFunctionList;
	CK_FLAGS flags;
} CK_INTERFACE;

typedef CK_INTERFACE CK_PTR CK_INTERFACE_PTR;
typedef CK_INTERFACE_PTR CK_PTR CK_INTERFACE_PTR_PTR;

typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

typedef struct CK_FUNCTION_LIST_3_0 CK_FUNCTION_LIST_3_0;
typedef CK_FUNCTION_LIST_3_0 CK_PTR CK_FUNCTION_LIST_3_0_PTR;
typedef CK_FUNCTION_LIST_3_0_PTR CK_PTR CK_FUNCTION_LIST_3_0_PTR_PTR;

typedef struct CK_FUNCTION_LIST_3_2 CK_FUNCTION_LIST_3_2;
typedef CK_FUNCTION_LIST_3_2 CK_PTR CK_FUNCTION_LIST_3_2_PTR;
typedef CK_FUNCTION_LIST_3_2_PTR CK_PTR CK_FUNCTION_LIST_3_2_PTR_PTR;

typedef CK_RV (CK_PTR CK_C_Initialize) (CK_VOID_PTR pReserved);
typedef CK_RV (CK_PTR CK_C_Finalize) (CK_VOID_PTR pReserved);
typedef CK_RV (CK_PTR CK_C_Terminate) (void);
typedef CK_RV (CK_PTR CK_C_GetInfo) (CK_INFO_PTR pInfo);
typedef CK_RV (CK_PTR CK_C_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR
					     ppFunctionList);
typedef CK_RV (CK_PTR CK_C_GetSlotList) (CK_BBOOL tokenPresent,
					 CK_SLOT_ID_PTR pSlotList,
					 CK_ULONG_PTR pusCount);
typedef CK_RV (CK_PTR CK_C_GetSlotInfo) (CK_SLOT_ID slotID,
					 CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (CK_PTR CK_C_GetTokenInfo) (CK_SLOT_ID slotID,
					  CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (CK_PTR CK_C_GetMechanismList) (CK_SLOT_ID slotID,
					      CK_MECHANISM_TYPE_PTR
					      pMechanismList,
					      CK_ULONG_PTR pusCount);
typedef CK_RV (CK_PTR CK_C_GetMechanismInfo) (CK_SLOT_ID slotID,
					      CK_MECHANISM_TYPE type,
					      CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (CK_PTR CK_C_InitToken) (CK_SLOT_ID slotID,
				       CK_CHAR_PTR pPin,
				       CK_ULONG usPinLen, CK_CHAR_PTR pLabel);
typedef CK_RV (CK_PTR CK_C_InitPIN) (CK_SESSION_HANDLE hSession,
				     CK_CHAR_PTR pPin, CK_ULONG usPinLen);
typedef CK_RV (CK_PTR CK_C_SetPIN) (CK_SESSION_HANDLE hSession,
				    CK_CHAR_PTR pOldPin,
				    CK_ULONG usOldLen,
				    CK_CHAR_PTR pNewPin, CK_ULONG usNewLen);
typedef CK_RV (CK_PTR CK_C_OpenSession) (CK_SLOT_ID slotID, CK_FLAGS flags,
					 CK_VOID_PTR pApplication,
					 CK_RV (*Notify)
					    (CK_SESSION_HANDLE hSession,
					     CK_NOTIFICATION event,
					     CK_VOID_PTR pApplication),
					 CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (CK_PTR CK_C_CloseSession) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_CloseAllSessions) (CK_SLOT_ID slotID);
typedef CK_RV (CK_PTR CK_C_GetSessionInfo) (CK_SESSION_HANDLE hSession,
					    CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (CK_PTR CK_C_GetOperationState) (CK_SESSION_HANDLE hSession,
					       CK_BYTE_PTR pOperationState,
					       CK_ULONG_PTR
						   pulOperationStateLen);
typedef CK_RV (CK_PTR CK_C_SetOperationState) (CK_SESSION_HANDLE hSession,
					       CK_BYTE_PTR pOperationState,
					       CK_ULONG ulOperationStateLen,
					       CK_OBJECT_HANDLE hEncryptionKey,
					       CK_OBJECT_HANDLE
						   hAuthenticationKey);
typedef CK_RV (CK_PTR CK_C_Login) (CK_SESSION_HANDLE hSession,
				   CK_USER_TYPE userType,
				   CK_CHAR_PTR pPin, CK_ULONG usPinLen);
typedef CK_RV (CK_PTR CK_C_Logout) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_CreateObject) (CK_SESSION_HANDLE hSession,
					  CK_ATTRIBUTE_PTR pTemplate,
					  CK_ULONG usCount,
					  CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (CK_PTR CK_C_CopyObject) (CK_SESSION_HANDLE hSession,
					CK_OBJECT_HANDLE hObject,
					CK_ATTRIBUTE_PTR pTemplate,
					CK_ULONG usCount,
					CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (CK_PTR CK_C_DestroyObject) (CK_SESSION_HANDLE hSession,
					   CK_OBJECT_HANDLE hObject);
typedef CK_RV (CK_PTR CK_C_GetObjectSize) (CK_SESSION_HANDLE hSession,
					   CK_OBJECT_HANDLE hObject,
					   CK_ULONG_PTR pusSize);
typedef CK_RV (CK_PTR CK_C_GetAttributeValue) (CK_SESSION_HANDLE hSession,
					       CK_OBJECT_HANDLE hObject,
					       CK_ATTRIBUTE_PTR pTemplate,
					       CK_ULONG usCount);
typedef CK_RV (CK_PTR CK_C_SetAttributeValue) (CK_SESSION_HANDLE hSession,
					       CK_OBJECT_HANDLE hObject,
					       CK_ATTRIBUTE_PTR pTemplate,
					       CK_ULONG usCount);
typedef CK_RV (CK_PTR CK_C_FindObjectsInit) (CK_SESSION_HANDLE hSession,
					     CK_ATTRIBUTE_PTR pTemplate,
					     CK_ULONG usCount);
typedef CK_RV (CK_PTR CK_C_FindObjects) (CK_SESSION_HANDLE hSession,
					 CK_OBJECT_HANDLE_PTR phObject,
					 CK_ULONG usMaxObjectCount,
					 CK_ULONG_PTR pusObjectCount);
typedef CK_RV (CK_PTR CK_C_FindObjectsFinal) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_EncryptInit) (CK_SESSION_HANDLE hSession,
					 CK_MECHANISM_PTR pMechanism,
					 CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_Encrypt) (CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pData,
				     CK_ULONG usDataLen,
				     CK_BYTE_PTR pEncryptedData,
				     CK_ULONG_PTR pusEncryptedDataLen);
typedef CK_RV (CK_PTR CK_C_EncryptUpdate) (CK_SESSION_HANDLE hSession,
					   CK_BYTE_PTR pPart,
					   CK_ULONG usPartLen,
					   CK_BYTE_PTR pEncryptedPart,
					   CK_ULONG_PTR pusEncryptedPartLen);
typedef CK_RV (CK_PTR CK_C_EncryptFinal) (CK_SESSION_HANDLE hSession,
					  CK_BYTE_PTR pLastEncryptedPart,
					  CK_ULONG_PTR pusLastEncryptedPartLen);
typedef CK_RV (CK_PTR CK_C_DecryptInit) (CK_SESSION_HANDLE hSession,
					 CK_MECHANISM_PTR pMechanism,
					 CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_Decrypt) (CK_SESSION_HANDLE hSession,
				     CK_BYTE_PTR pEncryptedData,
				     CK_ULONG usEncryptedDataLen,
				     CK_BYTE_PTR pData,
				     CK_ULONG_PTR pusDataLen);
typedef CK_RV (CK_PTR CK_C_DecryptUpdate) (CK_SESSION_HANDLE hSession,
					   CK_BYTE_PTR pEncryptedPart,
					   CK_ULONG usEncryptedPartLen,
					   CK_BYTE_PTR pPart,
					   CK_ULONG_PTR pusPartLen);
typedef CK_RV (CK_PTR CK_C_DecryptFinal) (CK_SESSION_HANDLE hSession,
					  CK_BYTE_PTR pLastPart,
					  CK_ULONG_PTR pusLastPartLen);
typedef CK_RV (CK_PTR CK_C_DigestInit) (CK_SESSION_HANDLE hSession,
					CK_MECHANISM_PTR pMechanism);
typedef CK_RV (CK_PTR CK_C_Digest) (CK_SESSION_HANDLE hSession,
				    CK_BYTE_PTR pData,
				    CK_ULONG usDataLen,
				    CK_BYTE_PTR pDigest,
				    CK_ULONG_PTR pusDigestLen);
typedef CK_RV (CK_PTR CK_C_DigestUpdate) (CK_SESSION_HANDLE hSession,
					  CK_BYTE_PTR pPart,
					  CK_ULONG usPartLen);
typedef CK_RV (CK_PTR CK_C_DigestKey) (CK_SESSION_HANDLE hSession,
				       CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_DigestFinal) (CK_SESSION_HANDLE hSession,
					 CK_BYTE_PTR pDigest,
					 CK_ULONG_PTR pusDigestLen);
typedef CK_RV (CK_PTR CK_C_SignInit) (CK_SESSION_HANDLE hSession,
				      CK_MECHANISM_PTR pMechanism,
				      CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_Sign) (CK_SESSION_HANDLE hSession,
				  CK_BYTE_PTR pData,
				  CK_ULONG usDataLen,
				  CK_BYTE_PTR pSignature,
				  CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR CK_C_SignUpdate) (CK_SESSION_HANDLE hSession,
					CK_BYTE_PTR pPart, CK_ULONG usPartLen);
typedef CK_RV (CK_PTR CK_C_SignFinal) (CK_SESSION_HANDLE hSession,
				       CK_BYTE_PTR pSignature,
				       CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR CK_C_SignRecoverInit) (CK_SESSION_HANDLE hSession,
					     CK_MECHANISM_PTR pMechanism,
					     CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_SignRecover) (CK_SESSION_HANDLE hSession,
					 CK_BYTE_PTR pData,
					 CK_ULONG usDataLen,
					 CK_BYTE_PTR pSignature,
					 CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR CK_C_VerifyInit) (CK_SESSION_HANDLE hSession,
					CK_MECHANISM_PTR pMechanism,
					CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_Verify) (CK_SESSION_HANDLE hSession,
				    CK_BYTE_PTR pData,
				    CK_ULONG usDataLen,
				    CK_BYTE_PTR pSignature,
				    CK_ULONG usSignatureLen);
typedef CK_RV (CK_PTR CK_C_VerifyUpdate) (CK_SESSION_HANDLE hSession,
					  CK_BYTE_PTR pPart,
					  CK_ULONG usPartLen);
typedef CK_RV (CK_PTR CK_C_VerifyFinal) (CK_SESSION_HANDLE hSession,
					 CK_BYTE_PTR pSignature,
					 CK_ULONG usSignatureLen);
typedef CK_RV (CK_PTR CK_C_VerifyRecoverInit) (CK_SESSION_HANDLE hSession,
					       CK_MECHANISM_PTR pMechanism,
					       CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_VerifyRecover) (CK_SESSION_HANDLE hSession,
					   CK_BYTE_PTR pSignature,
					   CK_ULONG usSignatureLen,
					   CK_BYTE_PTR pData,
					   CK_ULONG_PTR pusDataLen);
typedef CK_RV (CK_PTR CK_C_DigestEncryptUpdate) (CK_SESSION_HANDLE hSession,
						 CK_BYTE_PTR pPart,
						 CK_ULONG ulPartLen,
						 CK_BYTE_PTR pEncryptedPart,
						 CK_ULONG_PTR
						     pulEncryptedPartLen);
typedef CK_RV (CK_PTR CK_C_DecryptDigestUpdate) (CK_SESSION_HANDLE hSession,
						 CK_BYTE_PTR pEncryptedPart,
						 CK_ULONG ulEncryptedPartLen,
						 CK_BYTE_PTR pPart,
						 CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_PTR CK_C_SignEncryptUpdate) (CK_SESSION_HANDLE hSession,
					       CK_BYTE_PTR pPart,
					       CK_ULONG ulPartLen,
					       CK_BYTE_PTR pEncryptedPart,
					       CK_ULONG_PTR
						   pulEncryptedPartLen);
typedef CK_RV (CK_PTR CK_C_DecryptVerifyUpdate) (CK_SESSION_HANDLE hSession,
						 CK_BYTE_PTR pEncryptedPart,
						 CK_ULONG ulEncryptedPartLen,
						 CK_BYTE_PTR pPart,
						 CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_PTR CK_C_GenerateKey) (CK_SESSION_HANDLE hSession,
					 CK_MECHANISM_PTR pMechanism,
					 CK_ATTRIBUTE_PTR pTemplate,
					 CK_ULONG usCount,
					 CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR CK_C_GenerateKeyPair) (CK_SESSION_HANDLE hSession,
					     CK_MECHANISM_PTR pMechanism,
					     CK_ATTRIBUTE_PTR
						 pPublicKeyTemplate,
					     CK_ULONG usPublicKeyAttributeCount,
					     CK_ATTRIBUTE_PTR
						 pPrivateKeyTemplate,
					     CK_ULONG
						 usPrivateKeyAttributeCount,
					     CK_OBJECT_HANDLE_PTR phPrivateKey,
					     CK_OBJECT_HANDLE_PTR phPublicKey);
typedef CK_RV (CK_PTR CK_C_WrapKey) (CK_SESSION_HANDLE hSession,
				     CK_MECHANISM_PTR pMechanism,
				     CK_OBJECT_HANDLE hWrappingKey,
				     CK_OBJECT_HANDLE hKey,
				     CK_BYTE_PTR pWrappedKey,
				     CK_ULONG_PTR pusWrappedKeyLen);
typedef CK_RV (CK_PTR CK_C_UnwrapKey) (CK_SESSION_HANDLE hSession,
				       CK_MECHANISM_PTR pMechanism,
				       CK_OBJECT_HANDLE hUnwrappingKey,
				       CK_BYTE_PTR pWrappedKey,
				       CK_ULONG usWrappedKeyLen,
				       CK_ATTRIBUTE_PTR pTemplate,
				       CK_ULONG usAttributeCount,
				       CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR CK_C_DeriveKey) (CK_SESSION_HANDLE hSession,
				       CK_MECHANISM_PTR pMechanism,
				       CK_OBJECT_HANDLE hBaseKey,
				       CK_ATTRIBUTE_PTR pTemplate,
				       CK_ULONG usAttributeCount,
				       CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR CK_C_SeedRandom) (CK_SESSION_HANDLE hSession,
					CK_BYTE_PTR pSeed, CK_ULONG usSeedLen);
typedef CK_RV (CK_PTR CK_C_GenerateRandom) (CK_SESSION_HANDLE hSession,
					    CK_BYTE_PTR pRandomData,
					    CK_ULONG usRandomLen);
typedef CK_RV (CK_PTR CK_C_GetFunctionStatus) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_CancelFunction) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_Notify) (CK_SESSION_HANDLE hSession,
				  CK_NOTIFICATION event,
				  CK_VOID_PTR pApplication);
typedef CK_RV (CK_PTR CK_C_WaitForSlotEvent) (CK_FLAGS flags,
					      CK_SLOT_ID_PTR pSlot,
					      CK_VOID_PTR pReserved);

typedef CK_RV (CK_PTR CK_C_GetInterfaceList) (CK_INTERFACE *pInterfaceList,
					      CK_ULONG *pulCount);
typedef CK_RV (CK_PTR CK_C_GetInterface) (CK_UTF8CHAR *pInterfaceName,
					  CK_VERSION *pVersion,
					  CK_INTERFACE **ppInterface,
					  CK_FLAGS flags);
typedef CK_RV (CK_PTR CK_C_LoginUser) (CK_SESSION_HANDLE hSession,
				    CK_USER_TYPE userType,
				    CK_UTF8CHAR *pPin, CK_ULONG ulPinLen,
				    CK_UTF8CHAR *pUsername,
				    CK_ULONG ulUsernameLen);
typedef CK_RV (CK_PTR CK_C_SessionCancel) (CK_SESSION_HANDLE hSession,
					   CK_FLAGS flags);
typedef CK_RV (CK_PTR CK_C_MessageEncryptInit) (CK_SESSION_HANDLE hSession,
						CK_MECHANISM *pMechanism,
						CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_EncryptMessage) (CK_SESSION_HANDLE hSession,
					    void *pParameter,
					    CK_ULONG ulParameterLen,
					    CK_BYTE *pAssociatedData,
					    CK_ULONG ulAssociatedDataLen,
					    CK_BYTE *pPlaintext,
					    CK_ULONG ulPlaintextLen,
					    CK_BYTE *pCiphertext,
					    CK_ULONG *pulCiphertextLen);
typedef CK_RV (CK_PTR CK_C_EncryptMessageBegin) (CK_SESSION_HANDLE hSession,
						 void *pParameter,
						 CK_ULONG ulParameterLen,
						 CK_BYTE *pAssociatedData,
						 CK_ULONG ulAssociatedDataLen);
typedef CK_RV (CK_PTR CK_C_EncryptMessageNext) (CK_SESSION_HANDLE hSession,
						void *pParameter,
						CK_ULONG ulParameterLen,
						CK_BYTE *pPlaintextPart,
						CK_ULONG ulPlaintextPartLen,
						CK_BYTE *pCiphertextPart,
						CK_ULONG *pulCiphertextPartLen,
						CK_ULONG flags);
typedef CK_RV (CK_PTR CK_C_MessageEncryptFinal) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_MessageDecryptInit) (CK_SESSION_HANDLE hSession,
						CK_MECHANISM *pMechanism,
						CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_DecryptMessage) (CK_SESSION_HANDLE hSession,
					    void *pParameter,
					    CK_ULONG ulParameterLen,
					    CK_BYTE *pAssociatedData,
					    CK_ULONG ulAssociatedDataLen,
					    CK_BYTE *pCiphertext,
					    CK_ULONG ulCiphertextLen,
					    CK_BYTE *pPlaintext,
					    CK_ULONG *pulPlaintextLen);
typedef CK_RV (CK_PTR CK_C_DecryptMessageBegin) (CK_SESSION_HANDLE hSession,
						 void *pParameter,
						 CK_ULONG ulParameterLen,
						 CK_BYTE *pAssociatedData,
						 CK_ULONG ulAssociatedDataLen);
typedef CK_RV (CK_PTR CK_C_DecryptMessageNext) (CK_SESSION_HANDLE hSession,
						void *pParameter,
						CK_ULONG ulParameterLen,
						CK_BYTE *pCiphertextPart,
						CK_ULONG ulCiphertextPartLen,
						CK_BYTE *pPlaintextPart,
						CK_ULONG *pulPlaintextPartLen,
						CK_FLAGS flags);
typedef CK_RV (CK_PTR CK_C_MessageDecryptFinal) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_MessageSignInit) (CK_SESSION_HANDLE hSession,
					     CK_MECHANISM *pMechanism,
					     CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_SignMessage) (CK_SESSION_HANDLE hSession,
					 void *pParameter,
					 CK_ULONG ulParameterLen,
					 CK_BYTE *pData,
					 CK_ULONG ulDataLen,
					 CK_BYTE *pSignature,
					 CK_ULONG *pulSignatureLen);
typedef CK_RV (CK_PTR CK_C_SignMessageBegin) (CK_SESSION_HANDLE hSession,
					      void *pParameter,
					      CK_ULONG ulParameterLen);
typedef CK_RV (CK_PTR CK_C_SignMessageNext) (CK_SESSION_HANDLE hSession,
					     void *pParameter,
					     CK_ULONG ulParameterLen,
					     CK_BYTE *pDataPart,
					     CK_ULONG ulDataPartLen,
					     CK_BYTE *pSignature,
					     CK_ULONG *pulSignatureLen);
typedef CK_RV (CK_PTR CK_C_MessageSignFinal) (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR CK_C_MessageVerifyInit) (CK_SESSION_HANDLE hSession,
					       CK_MECHANISM *pMechanism,
					       CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR CK_C_VerifyMessage) (CK_SESSION_HANDLE hSession,
					   void *pParameter,
					   CK_ULONG ulParameterLen,
					   CK_BYTE *pData,
					   CK_ULONG ulDataLen,
					   CK_BYTE *pSignature,
					   CK_ULONG ulSignatureLen);
typedef CK_RV (CK_PTR CK_C_VerifyMessageBegin) (CK_SESSION_HANDLE hSession,
						void *pParameter,
						CK_ULONG ulParameterLen);
typedef CK_RV (CK_PTR CK_C_VerifyMessageNext) (CK_SESSION_HANDLE hSession,
					       void *pParameter,
					       CK_ULONG ulParameterLen,
					       CK_BYTE *pDataPart,
					       CK_ULONG ulDataPartLen,
					       CK_BYTE *pSignature,
					       CK_ULONG ulSignatureLen);
typedef CK_RV (CK_PTR CK_C_MessageVerifyFinal) (CK_SESSION_HANDLE hSession);

typedef CK_RV (CK_PTR CK_C_EncapsulateKey) (CK_SESSION_HANDLE hSession,
					    CK_MECHANISM_PTR pMechanism,
					    CK_OBJECT_HANDLE hPublicKey,
					    CK_ATTRIBUTE_PTR pTemplate,
					    CK_ULONG ulAttributeCount,
					    CK_BYTE_PTR pCiphertext,
					    CK_ULONG_PTR pulCiphertextLen,
					    CK_OBJECT_HANDLE_PTR phKey);

typedef CK_RV (CK_PTR CK_C_DecapsulateKey) (CK_SESSION_HANDLE hSession,
					    CK_MECHANISM_PTR pMechanism,
					    CK_OBJECT_HANDLE hPrivateKey,
					    CK_ATTRIBUTE_PTR pTemplate,
					    CK_ULONG ulAttributeCount,
					    CK_BYTE_PTR pCiphertext,
					    CK_ULONG ulCiphertextLen,
					    CK_OBJECT_HANDLE_PTR phKey);

typedef CK_RV (CK_PTR CK_C_VerifySignatureInit) (CK_SESSION_HANDLE hSession,
						 CK_MECHANISM_PTR pMechanism,
						 CK_OBJECT_HANDLE hKey,
						 CK_BYTE_PTR pSignature,
						 CK_ULONG ulSignatureLen);

typedef CK_RV (CK_PTR CK_C_VerifySignature) (CK_SESSION_HANDLE hSession,
					     CK_BYTE_PTR pData,
					     CK_ULONG ulDataLen);

typedef CK_RV (CK_PTR CK_C_VerifySignatureUpdate) (CK_SESSION_HANDLE hSession,
						   CK_BYTE_PTR pPart,
						   CK_ULONG ulPartLen);

typedef CK_RV (CK_PTR CK_C_VerifySignatureFinal) (CK_SESSION_HANDLE hSession);

typedef CK_RV (CK_PTR CK_C_GetSessionValidationFlags) (CK_SESSION_HANDLE hSession,
						       CK_SESSION_VALIDATION_FLAGS_TYPE type,
						       CK_FLAGS_PTR pFlags);

typedef CK_RV (CK_PTR CK_C_AsyncComplete) (CK_SESSION_HANDLE hSession,
					   CK_UTF8CHAR_PTR pFunctionName,
					   CK_ASYNC_DATA_PTR pResult);

typedef CK_RV (CK_PTR CK_C_AsyncGetID) (CK_SESSION_HANDLE hSession,
					CK_UTF8CHAR_PTR pFunctionName,
					CK_ULONG_PTR pulID);

typedef CK_RV (CK_PTR CK_C_AsyncJoin) (CK_SESSION_HANDLE hSession,
				       CK_UTF8CHAR_PTR pFunctionName,
				       CK_ULONG ulID,
				       CK_BYTE_PTR pData,
				       CK_ULONG ulData);

typedef CK_RV (CK_PTR CK_C_WrapKeyAuthenticated) (CK_SESSION_HANDLE hSession,
						  CK_MECHANISM_PTR pMechanism,
						  CK_OBJECT_HANDLE hWrappingKey,
						  CK_OBJECT_HANDLE hKey,
						  CK_BYTE_PTR pAssociatedData,
						  CK_ULONG ulAssociatedDataLen,
						  CK_BYTE_PTR pWrappedKey,
						  CK_ULONG_PTR pulWrappedKeyLen);

typedef CK_RV (CK_PTR CK_C_UnwrapKeyAuthenticated) (CK_SESSION_HANDLE hSession,
						    CK_MECHANISM_PTR pMechanism,
						    CK_OBJECT_HANDLE hUnwrappingKey,
						    CK_BYTE_PTR pWrappedKey,
						    CK_ULONG ulWrappedKeyLen,
						    CK_ATTRIBUTE_PTR pTemplate,
						    CK_ULONG ulAttributeCount,
						    CK_BYTE_PTR pAssociatedData,
						    CK_ULONG ulAssociatedDataLen,
						    CK_OBJECT_HANDLE_PTR phKey);

struct CK_FUNCTION_LIST {
	CK_VERSION version;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_C_GetMechanismInfo C_GetMechanismInfo;
	CK_C_InitToken C_InitToken;
	CK_C_InitPIN C_InitPIN;
	CK_C_SetPIN C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_C_CloseAllSessions C_CloseAllSessions;
	CK_C_GetSessionInfo C_GetSessionInfo;
	CK_C_GetOperationState C_GetOperationState;
	CK_C_SetOperationState C_SetOperationState;
	CK_C_Login C_Login;
	CK_C_Logout C_Logout;
	CK_C_CreateObject C_CreateObject;
	CK_C_CopyObject C_CopyObject;
	CK_C_DestroyObject C_DestroyObject;
	CK_C_GetObjectSize C_GetObjectSize;
	CK_C_GetAttributeValue C_GetAttributeValue;
	CK_C_SetAttributeValue C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_C_EncryptInit C_EncryptInit;
	CK_C_Encrypt C_Encrypt;
	CK_C_EncryptUpdate C_EncryptUpdate;
	CK_C_EncryptFinal C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_C_DecryptUpdate C_DecryptUpdate;
	CK_C_DecryptFinal C_DecryptFinal;
	CK_C_DigestInit C_DigestInit;
	CK_C_Digest C_Digest;
	CK_C_DigestUpdate C_DigestUpdate;
	CK_C_DigestKey C_DigestKey;
	CK_C_DigestFinal C_DigestFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_C_SignUpdate C_SignUpdate;
	CK_C_SignFinal C_SignFinal;
	CK_C_SignRecoverInit C_SignRecoverInit;
	CK_C_SignRecover C_SignRecover;
	CK_C_VerifyInit C_VerifyInit;
	CK_C_Verify C_Verify;
	CK_C_VerifyUpdate C_VerifyUpdate;
	CK_C_VerifyFinal C_VerifyFinal;
	CK_C_VerifyRecoverInit C_VerifyRecoverInit;
	CK_C_VerifyRecover C_VerifyRecover;
	CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_C_SignEncryptUpdate C_SignEncryptUpdate;
	CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_C_GenerateKey C_GenerateKey;
	CK_C_GenerateKeyPair C_GenerateKeyPair;
	CK_C_WrapKey C_WrapKey;
	CK_C_UnwrapKey C_UnwrapKey;
	CK_C_DeriveKey C_DeriveKey;
	CK_C_SeedRandom C_SeedRandom;
	CK_C_GenerateRandom C_GenerateRandom;
	CK_C_GetFunctionStatus C_GetFunctionStatus;
	CK_C_CancelFunction C_CancelFunction;
	CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

struct CK_FUNCTION_LIST_3_0 {
	CK_VERSION version;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_C_GetMechanismInfo C_GetMechanismInfo;
	CK_C_InitToken C_InitToken;
	CK_C_InitPIN C_InitPIN;
	CK_C_SetPIN C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_C_CloseAllSessions C_CloseAllSessions;
	CK_C_GetSessionInfo C_GetSessionInfo;
	CK_C_GetOperationState C_GetOperationState;
	CK_C_SetOperationState C_SetOperationState;
	CK_C_Login C_Login;
	CK_C_Logout C_Logout;
	CK_C_CreateObject C_CreateObject;
	CK_C_CopyObject C_CopyObject;
	CK_C_DestroyObject C_DestroyObject;
	CK_C_GetObjectSize C_GetObjectSize;
	CK_C_GetAttributeValue C_GetAttributeValue;
	CK_C_SetAttributeValue C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_C_EncryptInit C_EncryptInit;
	CK_C_Encrypt C_Encrypt;
	CK_C_EncryptUpdate C_EncryptUpdate;
	CK_C_EncryptFinal C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_C_DecryptUpdate C_DecryptUpdate;
	CK_C_DecryptFinal C_DecryptFinal;
	CK_C_DigestInit C_DigestInit;
	CK_C_Digest C_Digest;
	CK_C_DigestUpdate C_DigestUpdate;
	CK_C_DigestKey C_DigestKey;
	CK_C_DigestFinal C_DigestFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_C_SignUpdate C_SignUpdate;
	CK_C_SignFinal C_SignFinal;
	CK_C_SignRecoverInit C_SignRecoverInit;
	CK_C_SignRecover C_SignRecover;
	CK_C_VerifyInit C_VerifyInit;
	CK_C_Verify C_Verify;
	CK_C_VerifyUpdate C_VerifyUpdate;
	CK_C_VerifyFinal C_VerifyFinal;
	CK_C_VerifyRecoverInit C_VerifyRecoverInit;
	CK_C_VerifyRecover C_VerifyRecover;
	CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_C_SignEncryptUpdate C_SignEncryptUpdate;
	CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_C_GenerateKey C_GenerateKey;
	CK_C_GenerateKeyPair C_GenerateKeyPair;
	CK_C_WrapKey C_WrapKey;
	CK_C_UnwrapKey C_UnwrapKey;
	CK_C_DeriveKey C_DeriveKey;
	CK_C_SeedRandom C_SeedRandom;
	CK_C_GenerateRandom C_GenerateRandom;
	CK_C_GetFunctionStatus C_GetFunctionStatus;
	CK_C_CancelFunction C_CancelFunction;
	CK_C_WaitForSlotEvent C_WaitForSlotEvent;

	CK_C_GetInterfaceList C_GetInterfaceList;
	CK_C_GetInterface C_GetInterface;
	CK_C_LoginUser C_LoginUser;
	CK_C_SessionCancel C_SessionCancel;
	CK_C_MessageEncryptInit C_MessageEncryptInit;
	CK_C_EncryptMessage C_EncryptMessage;
	CK_C_EncryptMessageBegin C_EncryptMessageBegin;
	CK_C_EncryptMessageNext C_EncryptMessageNext;
	CK_C_MessageEncryptFinal C_MessageEncryptFinal;
	CK_C_MessageDecryptInit C_MessageDecryptInit;
	CK_C_DecryptMessage C_DecryptMessage;
	CK_C_DecryptMessageBegin C_DecryptMessageBegin;
	CK_C_DecryptMessageNext C_DecryptMessageNext;
	CK_C_MessageDecryptFinal C_MessageDecryptFinal;
	CK_C_MessageSignInit C_MessageSignInit;
	CK_C_SignMessage C_SignMessage;
	CK_C_SignMessageBegin C_SignMessageBegin;
	CK_C_SignMessageNext C_SignMessageNext;
	CK_C_MessageSignFinal C_MessageSignFinal;
	CK_C_MessageVerifyInit C_MessageVerifyInit;
	CK_C_VerifyMessage C_VerifyMessage;
	CK_C_VerifyMessageBegin C_VerifyMessageBegin;
	CK_C_VerifyMessageNext C_VerifyMessageNext;
	CK_C_MessageVerifyFinal C_MessageVerifyFinal;
};

struct CK_FUNCTION_LIST_3_2 {
	CK_VERSION version;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_C_GetMechanismInfo C_GetMechanismInfo;
	CK_C_InitToken C_InitToken;
	CK_C_InitPIN C_InitPIN;
	CK_C_SetPIN C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_C_CloseAllSessions C_CloseAllSessions;
	CK_C_GetSessionInfo C_GetSessionInfo;
	CK_C_GetOperationState C_GetOperationState;
	CK_C_SetOperationState C_SetOperationState;
	CK_C_Login C_Login;
	CK_C_Logout C_Logout;
	CK_C_CreateObject C_CreateObject;
	CK_C_CopyObject C_CopyObject;
	CK_C_DestroyObject C_DestroyObject;
	CK_C_GetObjectSize C_GetObjectSize;
	CK_C_GetAttributeValue C_GetAttributeValue;
	CK_C_SetAttributeValue C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_C_EncryptInit C_EncryptInit;
	CK_C_Encrypt C_Encrypt;
	CK_C_EncryptUpdate C_EncryptUpdate;
	CK_C_EncryptFinal C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_C_DecryptUpdate C_DecryptUpdate;
	CK_C_DecryptFinal C_DecryptFinal;
	CK_C_DigestInit C_DigestInit;
	CK_C_Digest C_Digest;
	CK_C_DigestUpdate C_DigestUpdate;
	CK_C_DigestKey C_DigestKey;
	CK_C_DigestFinal C_DigestFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_C_SignUpdate C_SignUpdate;
	CK_C_SignFinal C_SignFinal;
	CK_C_SignRecoverInit C_SignRecoverInit;
	CK_C_SignRecover C_SignRecover;
	CK_C_VerifyInit C_VerifyInit;
	CK_C_Verify C_Verify;
	CK_C_VerifyUpdate C_VerifyUpdate;
	CK_C_VerifyFinal C_VerifyFinal;
	CK_C_VerifyRecoverInit C_VerifyRecoverInit;
	CK_C_VerifyRecover C_VerifyRecover;
	CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_C_SignEncryptUpdate C_SignEncryptUpdate;
	CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_C_GenerateKey C_GenerateKey;
	CK_C_GenerateKeyPair C_GenerateKeyPair;
	CK_C_WrapKey C_WrapKey;
	CK_C_UnwrapKey C_UnwrapKey;
	CK_C_DeriveKey C_DeriveKey;
	CK_C_SeedRandom C_SeedRandom;
	CK_C_GenerateRandom C_GenerateRandom;
	CK_C_GetFunctionStatus C_GetFunctionStatus;
	CK_C_CancelFunction C_CancelFunction;
	CK_C_WaitForSlotEvent C_WaitForSlotEvent;

	CK_C_GetInterfaceList C_GetInterfaceList;
	CK_C_GetInterface C_GetInterface;
	CK_C_LoginUser C_LoginUser;
	CK_C_SessionCancel C_SessionCancel;
	CK_C_MessageEncryptInit C_MessageEncryptInit;
	CK_C_EncryptMessage C_EncryptMessage;
	CK_C_EncryptMessageBegin C_EncryptMessageBegin;
	CK_C_EncryptMessageNext C_EncryptMessageNext;
	CK_C_MessageEncryptFinal C_MessageEncryptFinal;
	CK_C_MessageDecryptInit C_MessageDecryptInit;
	CK_C_DecryptMessage C_DecryptMessage;
	CK_C_DecryptMessageBegin C_DecryptMessageBegin;
	CK_C_DecryptMessageNext C_DecryptMessageNext;
	CK_C_MessageDecryptFinal C_MessageDecryptFinal;
	CK_C_MessageSignInit C_MessageSignInit;
	CK_C_SignMessage C_SignMessage;
	CK_C_SignMessageBegin C_SignMessageBegin;
	CK_C_SignMessageNext C_SignMessageNext;
	CK_C_MessageSignFinal C_MessageSignFinal;
	CK_C_MessageVerifyInit C_MessageVerifyInit;
	CK_C_VerifyMessage C_VerifyMessage;
	CK_C_VerifyMessageBegin C_VerifyMessageBegin;
	CK_C_VerifyMessageNext C_VerifyMessageNext;
	CK_C_MessageVerifyFinal C_MessageVerifyFinal;

	CK_C_EncapsulateKey C_EncapsulateKey;
	CK_C_DecapsulateKey C_DecapsulateKey;
	CK_C_VerifySignatureInit C_VerifySignatureInit;
	CK_C_VerifySignature C_VerifySignature;
	CK_C_VerifySignatureUpdate C_VerifySignatureUpdate;
	CK_C_VerifySignatureFinal C_VerifySignatureFinal;
	CK_C_GetSessionValidationFlags C_GetSessionValidationFlags;
	CK_C_AsyncComplete C_AsyncComplete;
	CK_C_AsyncGetID C_AsyncGetID;
	CK_C_AsyncJoin C_AsyncJoin;
	CK_C_WrapKeyAuthenticated C_WrapKeyAuthenticated;
	CK_C_UnwrapKeyAuthenticated C_UnwrapKeyAuthenticated;
};

#ifdef __cplusplus
}
#endif

#endif
