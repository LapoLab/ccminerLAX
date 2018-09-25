#pragma once

#include "miner.h"

EXTC_BEGIN

struct synchronize {
	pthread_mutex_t lock;
	volatile int32_t counter;
	volatile uint8_t flagged;
};

extern void sync_set(struct synchronize * s);
extern void sync_reset(struct synchronize * s);

extern void sync_init(struct synchronize * s);
extern void sync_wait(struct synchronize * s);

extern void sync_free(struct synchronize * s);

extern void sync_set_wait_reset(struct synchronize * s);

extern struct synchronize * opt_miner_thread_sync;

EXTC_END;