#include "thread_sync.h"

EXTC_BEGIN

static inline bool try_lock(pthread_mutex_t * lock)
{
	int error = pthread_mutex_lock(lock);

	if (error == 0)
		return true;
	
	applog(LOG_ERR, "%s: lock error received: %i", __FUNCTION__, error);
	return false;
}

static inline void try_unlock(pthread_mutex_t * lock)
{
	int error = pthread_mutex_unlock(lock);

	if (error != 0)
		applog(LOG_ERR, "%s: unlock error received: %i", __FUNCTION__, error);
}

synchronize * opt_miner_thread_sync = nullptr;

#define syncnullcheckret												\
	if (!s) {															\
		applog(LOG_ERR, "%s null sync object received!", __FUNCTION__);	\
		return;															\
	} 

void sync_set(struct synchronize * s)
{
	syncnullcheckret

	if (try_lock(&s->lock)) {
		s->counter--;
		try_unlock(&s->lock);
	}
}

void sync_reset(struct synchronize * s)
{
	syncnullcheckret

	if (try_lock(&s->lock)) {
		s->counter++;

		if (s->counter >= opt_n_threads)
			s->flagged = false;

		try_unlock(&s->lock);
	}
}

void sync_init(struct synchronize * s)
{
	syncnullcheckret

	memset(s, 0, sizeof(*s));

	s->counter = opt_n_threads;

	int error = pthread_mutex_init(&s->lock, nullptr);

	if (error != 0) {
		applog(LOG_ERR, "%s: could not create lock. Error code: %i", __FUNCTION__, error);
	}
}

void sync_wait(struct synchronize * s)
{
	syncnullcheckret

	while (true) {
		if (try_lock(&s->lock)) {
			volatile bool flagged = false;
			
			if (s->counter <= 0)
				s->flagged = true;

			flagged = s->flagged;
			try_unlock(&s->lock);

			if (flagged)
				break;
		} else {
			applog(LOG_ERR, "%s: could not lock...bailing", __FUNCTION__);
			break;
		}

		usleep(100000);
	}
}

void sync_free(struct synchronize * s)
{
	syncnullcheckret

	int error = pthread_mutex_destroy(&s->lock);

	if (error != 0) {
		applog(LOG_ERR, "%s: could not destroy mutex. error received: %i", __FUNCTION__, error);
	}

	memset(s, 0, sizeof(*s));
}

void sync_set_wait_reset(struct synchronize * s)
{
	syncnullcheckret

	sync_set(s);
	sync_wait(s);
	sync_reset(s);
}

#undef syncnullcheckret

EXTC_END