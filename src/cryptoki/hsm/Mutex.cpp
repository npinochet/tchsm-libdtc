
#include "Mutex.h"
#include "TcbError.h"
#include "OSMutex.h"

using namespace hsm;

void Mutex::setFunctions(CK_CREATEMUTEX createMutex,
                         CK_DESTROYMUTEX destroyMutex,
                         CK_LOCKMUTEX lockMutex,
                         CK_UNLOCKMUTEX unlockMutex) {
    createMutex_ = createMutex;
    destroyMutex_ = destroyMutex;
    lockMutex_ = lockMutex;
    unlockMutex_ = unlockMutex;
}

Mutex::Mutex() : isLocked_(false) {
    CK_RV rv = createMutex_(&mutex_);
    if (rv != CKR_OK) {
        throw TcbError("Mutex::Mutex", "Could not create mutex!", rv);
    }
}

Mutex::~Mutex() {
    if (isLocked_) {
        CK_RV rv = unlockMutex_(mutex_); 
        if (rv != CKR_OK) {
            throw TcbError("Mutex::~Mutex", "Could not destroy mutex!", rv);
        }
    }
}

void Mutex::lock() {
    if (isLocked_) {
        throw TcbError("Mutex::lock", "Tried to lock an already locked mutex!", CKR_MUTEX_BAD);
    }
    CK_RV rv = lockMutex_(mutex_);
    if (rv != CKR_OK) {
        throw TcbError("Mutex::lock", "Mutex error!", rv);
    }
}

void Mutex::unlock() {
    if (!isLocked_) {
        throw TcbError("Mutex::unlock", "Tried to unlock an not locked mutex!", CKR_MUTEX_BAD);
    }
    CK_RV rv = unlockMutex_(mutex_);
    if (rv != CKR_OK) {
        throw TcbError("Mutex::lock", "Mutex error!", rv);
    }
}

// Default mutex functions (pthread ones!)
CK_CREATEMUTEX Mutex::createMutex_ = OSCreateMutex;
CK_DESTROYMUTEX destroyMutex_ = OSDestroyMutex;
CK_LOCKMUTEX lockMutex_ = OSLockMutex;
CK_UNLOCKMUTEX unlockMutex_ = OSUnlockMutex;
