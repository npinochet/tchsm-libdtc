/*
 * Copyright (c) 2016      Francisco Cifuentes, NIC Chile Research Labs
 * Copyright (c) 2008-2010 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2010      SURFnet bv
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 osmutex.cpp

 Contains OS-specific implementations of intraprocess mutex functions. This
 implementation is based on SoftHSM v1
 *****************************************************************************/

#include "OSMutex.h"

#include <stdlib.h>
#include <pthread.h>

using namespace hsm;

CK_RV hsm::OSCreateMutex(CK_VOID_PTR_PTR newMutex)
{
	int rv;

	/* Allocate memory */
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));

	if (pthreadMutex == NULL)
	{
		return CKR_HOST_MEMORY;
	}

	/* Initialise the mutex */
	if ((rv = pthread_mutex_init(pthreadMutex, NULL)) != 0)
	{
		free(pthreadMutex);
		return CKR_GENERAL_ERROR;
	}

	*newMutex = (CK_VOID_PTR) pthreadMutex;

	return CKR_OK;
}

CK_RV hsm::OSDestroyMutex(CK_VOID_PTR mutex)
{
	int rv;
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) mutex;

	if (pthreadMutex == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if ((rv = pthread_mutex_destroy(pthreadMutex)) != 0)
	{
		return CKR_GENERAL_ERROR;
	}

	free(pthreadMutex);

	return CKR_OK;
}

CK_RV hsm::OSLockMutex(CK_VOID_PTR mutex)
{
	int rv;
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) mutex;

	if (pthreadMutex == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if ((rv = pthread_mutex_lock(pthreadMutex)) != 0)
	{
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_RV hsm::OSUnlockMutex(CK_VOID_PTR mutex)
{
	int rv;
	pthread_mutex_t* pthreadMutex = (pthread_mutex_t*) mutex;

	if (pthreadMutex == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if ((rv = pthread_mutex_unlock(pthreadMutex)) != 0)
	{
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

CK_RV hsm::VoidCreateMutex(CK_VOID_PTR_PTR newMutex) {
    *newMutex = nullptr;
    return CKR_OK;
}

CK_RV hsm::VoidDestroyMutex(CK_VOID_PTR mutex) {
    return CKR_OK;
}

CK_RV hsm::VoidLockMutex(CK_VOID_PTR mutex) {
    return CKR_OK;
}

CK_RV hsm::VoidUnlockMutex(CK_VOID_PTR mutex) {
    return CKR_OK;
}
