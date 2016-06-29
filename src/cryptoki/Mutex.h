#include <memory>
#include <pkcs11.h>

#ifndef HSM_MUTEX_H
#define HSM_MUTEX_H

namespace hsm {

    class Mutex {
        public:
            Mutex();
            virtual ~Mutex();
            void lock();
            void unlock();
            static void setFunctions(CK_CREATEMUTEX createMutex,
                    CK_DESTROYMUTEX destroyMutex,
                    CK_LOCKMUTEX lockMutex,
                    CK_UNLOCKMUTEX unlockMutex);

        private:
            CK_VOID_PTR mutex_;
            bool isLocked_;

            /* To be used from the constructor */
            static CK_CREATEMUTEX createMutex_;
            static CK_DESTROYMUTEX destroyMutex_;
            static CK_LOCKMUTEX lockMutex_;
            static CK_UNLOCKMUTEX unlockMutex_;

    };

    class ScopedMutexLocker {
        Mutex &mutex_;
        public:
            ScopedMutexLocker(Mutex &mutex);
            virtual ~ScopedMutexLocker();
    };
}

#endif // HSM_MUTEX_H
