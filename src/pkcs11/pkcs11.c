// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <pthread.h>
#include "pkcs11.h"
#include "openssl.h"
#include "config.h"
#include "object.h"
#include "session.h"
#include "signature.h"

#define PKCS11_MANUFACTURER	"IBM"
#define PKCS11_LIBRARY_DESC	"ZPC PKCS#11 provider"
#define PKCS11_SLOT_DESC	"ZPC PKCS#11 slot"
#define PKCS11_TOKEN_LABEL	"ZPC"
#define PKCS11_TOKEN_MODEL	"ZPC"
#define PKCS11_TOKEN_SN		"01"
#define PKCS11_SLOT_NUMBER	0

#define UNUSED(x)   (void)(x)

CK_RV C_Finalize(CK_VOID_PTR pReserved);

/*
 * As per PKCS#11 spec, C_Initialize and C_Finalize are both single-threaded.
 * It is the application's responsibility to ensure C_Initialize and C_Finalize
 * are not called concurrently with each other or with any other C_ function.
 * This no locking is needed or the api_initialized flag.
 */
static volatile CK_BBOOL api_initialized = CK_FALSE;
static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;

static struct {
	CK_MECHANISM_TYPE type;
	CK_MECHANISM_INFO info;
} mech_list[] = {
	{ CKM_ECDSA, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA1, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA224, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA256, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA384, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA512, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_224, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_256, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_384, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_512, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_EDDSA, {255, 448, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_COMPRESS}},
};
static size_t mech_list_len = sizeof(mech_list) / sizeof(mech_list[0]);

/* General purpose functions */

static void child_fork_initializer(void)
{
	C_Finalize(NULL);
}

static void register_atfork(void)
{
	pthread_atfork(NULL, NULL, child_fork_initializer);
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_C_INITIALIZE_ARGS *pArgs = pInitArgs;

	if (api_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (pArgs) {
		if (pArgs->pReserved)
			return CKR_ARGUMENTS_BAD;
		if ((pArgs->flags & CKF_OS_LOCKING_OK) == 0 &&
		    (pArgs->CreateMutex || pArgs->DestroyMutex ||
		     pArgs->LockMutex || pArgs->UnlockMutex))
			return CKR_CANT_LOCK;
	}

	if (openssl_init() != 1)
		goto cleanup;

	if (session_list_init() != 1)
		goto cleanup;

	if (object_list_init() != 1)
		goto cleanup;

	if (config_process(openssl_process_config) != 1)
		goto cleanup;

	pthread_once(&atfork_once, register_atfork);

	api_initialized = CK_TRUE;
	return CKR_OK;

cleanup:
	object_list_term();
	session_list_term();
	openssl_term();
	return CKR_FUNCTION_FAILED;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	if (pReserved)
		return CKR_ARGUMENTS_BAD;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	object_list_term();
	session_list_term();
	openssl_term();

	api_initialized = CK_FALSE;
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	pInfo->cryptokiVersion.major = 3;
	pInfo->cryptokiVersion.minor = 2;

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MANUFACTURER,
	       strlen(PKCS11_MANUFACTURER));

	pInfo->flags = 0;

	memset(pInfo->libraryDescription, ' ',
	       sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_LIBRARY_DESC,
	       strlen(PKCS11_LIBRARY_DESC));

	pInfo->libraryVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->libraryVersion.minor = ZPCPKCS11_VERSION_MINOR;

	return CKR_OK;
}

/* Slot and token management functions */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR pulCount)
{
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	(void)tokenPresent;

	if (pSlotList) {
		if (*pulCount < 1)
			return CKR_BUFFER_TOO_SMALL;

		pSlotList[0] = PKCS11_SLOT_NUMBER;
	}

	*pulCount = 1;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_SLOT_DESC,
	       strlen(PKCS11_SLOT_DESC));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MANUFACTURER,
	       strlen(PKCS11_MANUFACTURER));

	pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	pInfo->hardwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	pInfo->firmwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_TOKEN_LABEL, strlen(PKCS11_TOKEN_LABEL));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MANUFACTURER,
	       strlen(PKCS11_MANUFACTURER));

	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, PKCS11_TOKEN_MODEL, strlen(PKCS11_TOKEN_MODEL));

	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, PKCS11_TOKEN_SN, strlen(PKCS11_TOKEN_SN));

	pInfo->flags = CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED |
		       CKF_TOKEN_INITIALIZED;

	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;

	if (!session_get_counts(&pInfo->ulSessionCount,
				&pInfo->ulRwSessionCount))
		return CKR_FUNCTION_FAILED;

	pInfo->ulMaxPinLen = CK_EFFECTIVELY_INFINITE;
	pInfo->ulMinPinLen = 0;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	pInfo->hardwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	pInfo->firmwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
			 CK_VOID_PTR pReserved)
{
	UNUSED(flags);
	UNUSED(pSlot);
	UNUSED(pReserved);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_ULONG i;

	if (!pulCount)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	if (!pMechanismList) {
		*pulCount = mech_list_len;
		return CKR_OK;
	}

	if (*pulCount < mech_list_len) {
		*pulCount = mech_list_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < mech_list_len; i++)
		pMechanismList[i] = mech_list[i].type;
	*pulCount = mech_list_len;

	return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	CK_ULONG i;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	for (i = 0; i < mech_list_len; i++) {
		if (mech_list[i].type == type) {
			*pInfo = mech_list[i].info;
			return CKR_OK;
		}
	}

	return CKR_MECHANISM_INVALID;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	UNUSED(slotID);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pLabel);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	UNUSED(hSession);
	UNUSED(pOldPin);
	UNUSED(ulOldLen);
	UNUSED(pNewPin);
	UNUSED(ulNewLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Session management functions */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	UNUSED(pApplication);
	UNUSED(Notify);

	if (!phSession)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;
	if ((flags & CKF_SERIAL_SESSION) == 0)
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	if ((flags & CKF_ASYNC_SESSION) != 0)
		return CKR_SESSION_ASYNC_NOT_SUPPORTED;

	if (!session_add_session(slotID, flags, phSession))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_remove_session(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	if (!session_remove_all())
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	struct pkcs11_session *sess;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	*pInfo = sess->info;
	return CKR_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(pulOperationStateLen);

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_STATE_UNSAVEABLE;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(ulOperationStateLen);
	UNUSED(hEncryptionKey);
	UNUSED(hAuthenticationKey);

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_STATE_UNSAVEABLE;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	struct pkcs11_session *sess;

	UNUSED(pPin);
	UNUSED(ulPinLen);

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (session_get_login_state() == CK_TRUE)
		return CKR_USER_ALREADY_LOGGED_IN;

	session_set_login_state(CK_TRUE);

	return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	struct pkcs11_session *sess;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (session_get_login_state() == CK_FALSE)
		return CKR_USER_NOT_LOGGED_IN;

	session_set_login_state(CK_FALSE);

	return CKR_OK;
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	struct pkcs11_session *sess;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!session_op_cleanup(sess, flags))
		return CKR_OPERATION_CANCEL_FAILED;

	return CKR_OK;
}

/* Object management functions */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	UNUSED(hSession);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phObject);
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		   CK_OBJECT_HANDLE_PTR phNewObject)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phNewObject);
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	UNUSED(hSession);
	UNUSED(hObject);
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *obj;

	if (!pulSize)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hObject, &obj))
		return CKR_OBJECT_HANDLE_INVALID;

	if (!object_get_size(obj, pulSize))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *obj;

	if (!pTemplate && ulCount != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hObject, &obj))
		return CKR_OBJECT_HANDLE_INVALID;

	return object_get_attributes(obj, pTemplate, ulCount);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pTemplate && ulCount != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_init(sess, CKF_FIND_OBJECTS);
	if (rc != CKR_OK)
		return rc;

	sess->find.pos = 0;
	if (!dyn_array_init(&sess->find.found)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (!object_list_find(pTemplate, ulCount, &sess->find.found)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

done:
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_FIND_OBJECTS);

	return rc;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *obj;
	CK_ULONG i;
	CK_RV rc;

	if (!phObject || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_FIND_OBJECTS);
	if (rc != CKR_OK)
		return rc;

	*pulObjectCount = 0;
	for (i = 0; i < ulMaxObjectCount; i++) {
		if (!dyn_array_get(&sess->find.found, sess->find.pos,
				   (void **)&obj))
			break;

		phObject[i] = obj->handle;
		(*pulObjectCount)++;
		sess->find.pos++;
	}

	return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_FIND_OBJECTS);
	if (rc != CKR_OK)
		return rc;

	session_op_cleanup(sess, CKF_FIND_OBJECTS);

	return CKR_OK;
}

/* Encryption functions */

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
	      CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_ENCRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pEncryptedData);
	UNUSED(pulEncryptedDataLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastEncryptedPart);
	UNUSED(pulLastEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Decryption functions */

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_DECRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedData);
	UNUSED(ulEncryptedDataLen);
	UNUSED(pData);
	UNUSED(pulDataLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastPart);
	UNUSED(pulLastPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Message digesting functions */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_DIGEST);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(hKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Signing and MACing functions */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *key;
	CK_RV rc;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_SIGN);

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hKey, &key))
		return CKR_OBJECT_HANDLE_INVALID;

	rc = session_op_init(sess, CKF_SIGN);
	if (rc != CKR_OK)
		return rc;

	rc = signature_sign_init(sess, key, pMechanism);
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_SIGN);

	return rc;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pulSignatureLen || (!pData && ulDataLen != 0))
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_single(sess, CKF_SIGN);
	if (rc != CKR_OK)
		return rc;

	rc = signature_sign(sess, pData, ulDataLen,
			    pSignature, pulSignatureLen);

	if (!((rc == CKR_OK && !pSignature) || rc == CKR_BUFFER_TOO_SMALL))
		session_op_cleanup(sess, CKF_SIGN);

	return rc;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pPart && ulPartLen != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_SIGN);
	if (rc != CKR_OK)
		return rc;

	rc = signature_sign_update(sess, pPart, ulPartLen);
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_SIGN);

	return rc;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pulSignatureLen)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_SIGN);
	if (rc != CKR_OK)
		return rc;

	rc = signature_sign_final(sess, pSignature, pulSignatureLen);

	if (!((rc == CKR_OK && !pSignature) || rc == CKR_BUFFER_TOO_SMALL))
		session_op_cleanup(sess, CKF_SIGN);

	return rc;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_SIGN_RECOVER);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Verifying signatures and MACs functions */

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *key;
	CK_RV rc;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_VERIFY);

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hKey, &key))
		return CKR_OBJECT_HANDLE_INVALID;

	rc = session_op_init(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify_init(sess, key, pMechanism, NULL, 0);
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pSignature || ulSignatureLen == 0 ||
	    (!pData && ulDataLen != 0))
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_single(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify(sess, pData, ulDataLen,
			      pSignature, ulSignatureLen);

	session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pPart && ulPartLen != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify_update(sess, pPart, ulPartLen);
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pSignature || ulSignatureLen == 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify_final(sess, pSignature, ulSignatureLen);

	session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_VERIFY_RECOVER);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	UNUSED(pData);
	UNUSED(pulDataLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Dual-function cryptographic functions */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Key management functions */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pPublicKeyTemplate);
	UNUSED(ulPublicKeyAttributeCount);
	UNUSED(pPrivateKeyTemplate);
	UNUSED(ulPrivateKeyAttributeCount);
	UNUSED(phPublicKey);
	UNUSED(phPrivateKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hWrappingKey);
	UNUSED(hKey);
	UNUSED(pWrappedKey);
	UNUSED(pulWrappedKeyLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hUnwrappingKey);
	UNUSED(pWrappedKey);
	UNUSED(ulWrappedKeyLen);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hBaseKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Random number generation functions */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	UNUSED(hSession);
	UNUSED(pSeed);
	UNUSED(ulSeedLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	UNUSED(hSession);
	UNUSED(pRandomData);
	UNUSED(ulRandomLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Parallel function management functions */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_PARALLEL;
}

/* Message-based encryption and decryption functions (v3.0) */

CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism,
			   CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_MESSAGE_ENCRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pPlaintext);
	UNUSED(ulPlaintextLen);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG ulPlaintextPartLen,
			   CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pPlaintextPart);
	UNUSED(ulPlaintextPartLen);
	UNUSED(pCiphertextPart);
	UNUSED(pulCiphertextPartLen);
	UNUSED(flags);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism,
			   CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_MESSAGE_DECRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG_PTR pulPlaintextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(pPlaintext);
	UNUSED(pulPlaintextLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG ulCiphertextPartLen,
			   CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pCiphertextPart);
	UNUSED(ulCiphertextPartLen);
	UNUSED(pPlaintextPart);
	UNUSED(pulPlaintextPartLen);
	UNUSED(flags);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Message-based signing and verification functions (v3.0) */

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_MESSAGE_SIGN);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		    CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			 CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	UNUSED(hKey);
	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_MESSAGE_VERIFY);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		      CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		      CK_ULONG ulDataLen,
		      CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			  CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			  CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* PKCS #11 v3.2 functions */

CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		  CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	struct pkcs11_session *sess;

	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pUsername);
	UNUSED(ulUsernameLen);

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (session_get_login_state() == CK_TRUE)
		return CKR_USER_ALREADY_LOGGED_IN;

	session_set_login_state(CK_TRUE);

	return CKR_OK;
}

CK_RV C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		       CK_OBJECT_HANDLE hPublicKey, CK_ATTRIBUTE_PTR pTemplate,
		       CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen,
		       CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hPublicKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);
	UNUSED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		       CK_OBJECT_HANDLE hPrivateKey, CK_ATTRIBUTE_PTR pTemplate,
		       CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hPrivateKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE hSession,
			    CK_MECHANISM_PTR pMechanism,
			    CK_OBJECT_HANDLE hKey,
			    CK_BYTE_PTR pSignature,
			    CK_ULONG ulSignatureLen)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *key;
	CK_RV rc;

	if (!pSignature || ulSignatureLen == 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pMechanism)
		return C_SessionCancel(hSession, CKF_VERIFY);

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hKey, &key))
		return CKR_OBJECT_HANDLE_INVALID;

	rc = session_op_init(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify_init(sess, key, pMechanism,
				   pSignature, ulSignatureLen);
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pData && ulDataLen != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_single(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify(sess, pData, ulDataLen,
			      sess->verify.signature,
			      sess->verify.signature_len);

	session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			      CK_ULONG ulPartLen)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!pPart && ulPartLen != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify_update(sess, pPart, ulPartLen);
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_VERIFY);
	if (rc != CKR_OK)
		return rc;

	rc = signature_verify_final(sess, sess->verify.signature,
				    sess->verify.signature_len);

	session_op_cleanup(sess, CKF_VERIFY);

	return rc;
}

CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession,
				  CK_SESSION_VALIDATION_FLAGS_TYPE type,
				  CK_FLAGS_PTR pFlags)
{
	UNUSED(hSession);
	UNUSED(type);
	UNUSED(pFlags);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		      CK_ASYNC_DATA_PTR pResult)
{
	UNUSED(hSession);
	UNUSED(pFunctionName);
	UNUSED(pResult);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		   CK_ULONG_PTR pulID)
{
	UNUSED(hSession);
	UNUSED(pFunctionName);
	UNUSED(pulID);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		  CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulData)
{
	UNUSED(hSession);
	UNUSED(pFunctionName);
	UNUSED(ulID);
	UNUSED(pData);
	UNUSED(ulData);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKeyAuthenticated(CK_SESSION_HANDLE hSession,
			     CK_MECHANISM_PTR pMechanism,
			     CK_OBJECT_HANDLE hWrappingKey,
			     CK_OBJECT_HANDLE hKey,
			     CK_BYTE_PTR pAssociatedData,
			     CK_ULONG ulAssociatedDataLen,
			     CK_BYTE_PTR pWrappedKey,
			     CK_ULONG_PTR pulWrappedKeyLen)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hWrappingKey);
	UNUSED(hKey);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pWrappedKey);
	UNUSED(pulWrappedKeyLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE hSession,
			       CK_MECHANISM_PTR pMechanism,
			       CK_OBJECT_HANDLE hUnwrappingKey,
			       CK_BYTE_PTR pWrappedKey,
			       CK_ULONG ulWrappedKeyLen,
			       CK_ATTRIBUTE_PTR pTemplate,
			       CK_ULONG ulAttributeCount,
			       CK_BYTE_PTR pAssociatedData,
			       CK_ULONG ulAssociatedDataLen,
			       CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hUnwrappingKey);
	UNUSED(pWrappedKey);
	UNUSED(ulWrappedKeyLen);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Interface lists and related functions */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList,
			 CK_ULONG_PTR pulCount);
CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
		     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags);

static CK_FUNCTION_LIST func_list_pkcs11_2_40 = {
	{2, 40},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

static CK_FUNCTION_LIST_3_0 func_list_pkcs11_3_0 = {
	{3, 0},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent,
	C_GetInterfaceList,
	C_GetInterface,
	C_LoginUser,
	C_SessionCancel,
	C_MessageEncryptInit,
	C_EncryptMessage,
	C_EncryptMessageBegin,
	C_EncryptMessageNext,
	C_MessageEncryptFinal,
	C_MessageDecryptInit,
	C_DecryptMessage,
	C_DecryptMessageBegin,
	C_DecryptMessageNext,
	C_MessageDecryptFinal,
	C_MessageSignInit,
	C_SignMessage,
	C_SignMessageBegin,
	C_SignMessageNext,
	C_MessageSignFinal,
	C_MessageVerifyInit,
	C_VerifyMessage,
	C_VerifyMessageBegin,
	C_VerifyMessageNext,
	C_MessageVerifyFinal
};

static CK_FUNCTION_LIST_3_2 func_list_pkcs11_3_2 = {
	{3, 2},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent,
	C_GetInterfaceList,
	C_GetInterface,
	C_LoginUser,
	C_SessionCancel,
	C_MessageEncryptInit,
	C_EncryptMessage,
	C_EncryptMessageBegin,
	C_EncryptMessageNext,
	C_MessageEncryptFinal,
	C_MessageDecryptInit,
	C_DecryptMessage,
	C_DecryptMessageBegin,
	C_DecryptMessageNext,
	C_MessageDecryptFinal,
	C_MessageSignInit,
	C_SignMessage,
	C_SignMessageBegin,
	C_SignMessageNext,
	C_MessageSignFinal,
	C_MessageVerifyInit,
	C_VerifyMessage,
	C_VerifyMessageBegin,
	C_VerifyMessageNext,
	C_MessageVerifyFinal,
	C_EncapsulateKey,
	C_DecapsulateKey,
	C_VerifySignatureInit,
	C_VerifySignature,
	C_VerifySignatureUpdate,
	C_VerifySignatureFinal,
	C_GetSessionValidationFlags,
	C_AsyncComplete,
	C_AsyncGetID,
	C_AsyncJoin,
	C_WrapKeyAuthenticated,
	C_UnwrapKeyAuthenticated
};

static CK_INTERFACE interfaces[] = {
	{
		(CK_UTF8CHAR *)"PKCS 11",
		&func_list_pkcs11_3_2,
		0
	},
	{
		(CK_UTF8CHAR *)"PKCS 11",
		&func_list_pkcs11_3_0,
		0
	},
	{
		(CK_UTF8CHAR *)"PKCS 11",
		&func_list_pkcs11_2_40,
		0
	},
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &func_list_pkcs11_2_40;
	return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList,
			 CK_ULONG_PTR pulCount)
{
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;

	if (!pInterfacesList) {
		*pulCount = sizeof(interfaces) / sizeof(interfaces[0]);
		return CKR_OK;
	}

	if (*pulCount < sizeof(interfaces) / sizeof(interfaces[0])) {
		*pulCount = sizeof(interfaces) / sizeof(interfaces[0]);
		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = sizeof(interfaces) / sizeof(interfaces[0]);
	for (CK_ULONG i = 0; i < *pulCount; i++)
		pInterfacesList[i] = interfaces[i];

	return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
		     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	CK_INTERFACE *interf;
	size_t i;

	if (!ppInterface)
		return CKR_ARGUMENTS_BAD;

	*ppInterface = NULL;
	for (i = 0; i < sizeof(interfaces) / sizeof(interfaces[0]); i++) {
		interf = &interfaces[i];

		if ((!pInterfaceName ||
		     strcmp((char *)pInterfaceName,
			    (char *)interf->pInterfaceName) == 0) &&
		    (!pVersion ||
		     (pVersion->major ==
			     ((CK_VERSION *)interf->pFunctionList)->major &&
		      pVersion->minor ==
			     ((CK_VERSION *)interf->pFunctionList)->minor)) &&
		    (flags == (interf->flags & flags))) {
			*ppInterface = interf;
			break;
		}
	}

	if (!*ppInterface)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}
