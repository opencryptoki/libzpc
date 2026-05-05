// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>
#include "session.h"
#include "utils.h"

/*
 * The session mutex protects the list structure only. Per the PKCS#11
 * spec a session may not be used concurrently by multiple threads,
 * so a session remains valid for the duration of the caller's
 * operation without holding the lock.
 */
static struct dyn_array sessions;
static CK_BBOOL global_login_state = CK_FALSE;
static pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

static void session_set_state(struct pkcs11_session *sess)
{
	if (global_login_state) {
		if ((sess->info.flags & CKF_RW_SESSION) != 0)
			sess->info.state = CKS_RW_USER_FUNCTIONS;
		else
			sess->info.state = CKS_RO_USER_FUNCTIONS;
	} else {
		if ((sess->info.flags & CKF_RW_SESSION) != 0)
			sess->info.state = CKS_RW_PUBLIC_SESSION;
		else
			sess->info.state = CKS_RO_PUBLIC_SESSION;
	}
}

int session_init(struct pkcs11_session **sess, CK_SLOT_ID slot, CK_FLAGS flags)
{
	struct pkcs11_session *s;

	if (!sess)
		return 0;

	s = calloc(1, sizeof(*s));
	if (!s)
		return 0;

	s->info.slotID = slot;
	s->info.flags = flags;

	if (pthread_mutex_lock(&session_mutex) != 0) {
		free(s);
		return 0;
	}

	session_set_state(s);

	pthread_mutex_unlock(&session_mutex);

	*sess = s;
	return 1;
}

CK_RV session_op_init(struct pkcs11_session *sess, CK_FLAGS op_flags)
{
	if (!sess)
		return CKR_ARGUMENTS_BAD;

	if ((sess->op_active & op_flags) != 0)
		return CKR_OPERATION_ACTIVE;

	sess->op_active |= op_flags;

	return CKR_OK;
}

CK_RV session_op_single(struct pkcs11_session *sess, CK_FLAGS op_flags)
{
	if (!sess)
		return CKR_ARGUMENTS_BAD;

	if ((sess->op_active & op_flags) != op_flags)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((sess->op_multi_init & op_flags) == 0) {
		sess->op_multi_init |= op_flags;
		sess->op_multi &= ~op_flags;
	}

	if ((sess->op_multi & op_flags) != 0)
		return CKR_OPERATION_ACTIVE;

	return CKR_OK;
}

CK_RV session_op_multi(struct pkcs11_session *sess, CK_FLAGS op_flags)
{
	if (!sess)
		return CKR_ARGUMENTS_BAD;

	if ((sess->op_active & op_flags) != op_flags)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((sess->op_multi_init & op_flags) == 0) {
		sess->op_multi_init |= op_flags;
		sess->op_multi |= op_flags;
	}

	if ((sess->op_multi & op_flags) != op_flags)
		return CKR_OPERATION_ACTIVE;

	return CKR_OK;
}

int session_op_cleanup(struct pkcs11_session *sess, CK_FLAGS op_flags)
{
	if (!sess)
		return 0;

	if (sess->op_active & op_flags & CKF_FIND_OBJECTS) {
		dyn_array_free(&sess->find.found);
		sess->find.pos = 0;
	}

	// TODO implement cleanup of operation state

	sess->op_active &= ~op_flags;
	sess->op_multi_init &= ~op_flags;
	sess->op_multi &= ~op_flags;

	return 1;
}

void session_free(struct pkcs11_session *sess)
{
	if (!sess)
		return;

	session_op_cleanup(sess, CKF_FIND_OBJECTS |
				 CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST |
				 CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY |
				 CKF_VERIFY_RECOVER | CKF_MESSAGE_ENCRYPT |
				 CKF_MESSAGE_DECRYPT | CKF_MESSAGE_SIGN |
				 CKF_MESSAGE_VERIFY);

	free(sess);
}

int session_list_init(void)
{
	int rc;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return 0;

	rc = dyn_array_init(&sessions);

	pthread_mutex_unlock(&session_mutex);

	return rc;
}

void session_list_term(void)
{
	struct pkcs11_session *sess;
	size_t i;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return;

	for (i = 0; i < dyn_array_size(&sessions); i++) {
		if (!dyn_array_get(&sessions, i, (void **)&sess))
			break;
		if (sess)
			session_free(sess);
	}

	dyn_array_free(&sessions);

	pthread_mutex_unlock(&session_mutex);
}

int session_add_session(CK_SLOT_ID slot, CK_FLAGS flags,
			CK_SESSION_HANDLE *handle)
{
	struct pkcs11_session *sess, *s;
	size_t index;

	if (!handle)
		return 0;

	if (!session_init(&sess, slot, flags))
		return 0;

	if (pthread_mutex_lock(&session_mutex) != 0) {
		session_free(sess);
		return 0;
	}

	for (index = 0; index < dyn_array_size(&sessions); index++) {
		if (!dyn_array_get(&sessions, index, (void **)&s))
			break;
		if (!s) {
			if (!dyn_array_set(&sessions, index, sess)) {
				session_free(sess);
				goto error;
			}
			goto done;
		}
	}

	if (!dyn_array_add(&sessions, sess, &index)) {
		session_free(sess);
		goto error;
	}

done:
	sess->handle = index + 1; /* zero handle = invalid */
	*handle = sess->handle;

	pthread_mutex_unlock(&session_mutex);
	return 1;

error:
	pthread_mutex_unlock(&session_mutex);
	return 0;
}

int session_get_session(CK_SESSION_HANDLE handle, struct pkcs11_session **sess)
{
	int rc = 0;

	if (handle == CK_INVALID_HANDLE)
		return 0;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return 0;

	if (!dyn_array_get(&sessions, handle - 1, (void **)sess))
		goto unlock;

	if (!*sess)
		goto unlock;

	rc = 1;

unlock:
	pthread_mutex_unlock(&session_mutex);

	return rc;
}

int session_remove_session(CK_SESSION_HANDLE handle)
{
	struct pkcs11_session *sess;
	int rc = 0;

	if (handle == CK_INVALID_HANDLE)
		return 0;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return 0;

	if (!dyn_array_get(&sessions, handle - 1, (void **)&sess))
		goto unlock;

	if (!sess)
		goto unlock;

	if (!dyn_array_set(&sessions, handle - 1, NULL))
		goto unlock;

	session_free(sess);

	rc = 1;

unlock:
	pthread_mutex_unlock(&session_mutex);

	return rc;
}

int session_remove_all(void)
{
	struct pkcs11_session *sess;
	size_t i;
	int rc = 0;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return 0;

	for (i = 0; i < dyn_array_size(&sessions); i++) {
		if (!dyn_array_get(&sessions, i, (void **)&sess))
			goto unlock;
		if (sess) {
			if (!dyn_array_set(&sessions, i, NULL))
				goto unlock;
			session_free(sess);
		}
	}

	rc = 1;

unlock:
	pthread_mutex_unlock(&session_mutex);

	return rc;
}

void session_set_login_state(CK_BBOOL login)
{
	struct pkcs11_session *sess;
	size_t i;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return;

	global_login_state = login;

	for (i = 0; i < dyn_array_size(&sessions); i++) {
		if (!dyn_array_get(&sessions, i, (void **)&sess))
			break;
		if (sess)
			session_set_state(sess);
	}

	pthread_mutex_unlock(&session_mutex);
}

CK_BBOOL session_get_login_state(void)
{
	CK_BBOOL ret;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return CK_FALSE;

	ret = global_login_state;

	pthread_mutex_unlock(&session_mutex);

	return ret;
}

int session_get_counts(CK_ULONG *count, CK_ULONG *rw_count)
{
	struct pkcs11_session *sess;
	size_t i;

	*count = 0;
	*rw_count = 0;

	if (pthread_mutex_lock(&session_mutex) != 0)
		return 0;

	for (i = 0; i < dyn_array_size(&sessions); i++) {
		if (!dyn_array_get(&sessions, i, (void **)&sess))
			break;
		if (!sess)
			continue;

		(*count)++;
		if (sess->info.flags & CKF_RW_SESSION)
			(*rw_count)++;
	}

	pthread_mutex_unlock(&session_mutex);
	return 1;
}
