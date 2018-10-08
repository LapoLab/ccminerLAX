#ifndef LYRA2ZZ_H_
#define LYRA2ZZ_H_

#include <stdint.h>
#include <string.h>
#include "curl\curl.h"

#define LYRA2ZZ_BLOCK_HEADER_LEN_BYTES 112
#define LYRA2ZZ_BLOCK_HEADER_NONCE_OFFSET 19 /* 19 * 4 bytes */

#define LYRA2ZZ_BLOCK_HEADER_UINT32_LEN 32

#define LYRA2ZZ_LOG_HEADER __func__ " lyra2zz - "

#ifdef __cplusplus
extern "C" {
#endif

enum {
	LYRA2ZZ_HEADER_UINT32_OFFSET_VERSION = 0,
	LYRA2ZZ_HEADER_UINT32_OFFSET_PREV_BLOCK = 1,
	LYRA2ZZ_HEADER_UINT32_OFFSET_MERKLE_ROOT = 9,
	LYRA2ZZ_HEADER_UINT32_OFFSET_TIME = 17,
	LYRA2ZZ_HEADER_UINT32_OFFSET_TARGET_ENCODED = 18,
	LYRA2ZZ_HEADER_UINT32_OFFSET_NONCE = 19,
	LYRA2ZZ_HEADER_UINT32_OFFSET_ACCUM_CHECKPOINT = 20,

	LYRA2ZZ_SIZE_PREV_BLOCK = 32,
	LYRA2ZZ_SIZE_MERKLE_ROOT = 32,
	LYRA2ZZ_SIZE_ACCUM_CHECKPOINT = 32
};

typedef uint32_t l2zz_uint256_32_t[8];
typedef uint32_t lyra2zz_header_data_t[LYRA2ZZ_BLOCK_HEADER_UINT32_LEN];

typedef struct lyra2zz_block_header {
	l2zz_uint256_32_t block_hash;
	l2zz_uint256_32_t target_decoded;
	
	uint8_t *byte_view; /* points to data (used for debugging) */
	
	uint32_t min_nonce;
	uint32_t max_nonce;

	lyra2zz_header_data_t data;

} lyra2zz_block_header_t;


class uint256;
struct json_t;

int lyra2Zz_submit(CURL *curl, struct pool_infos *pools, struct work *work);

/* gbt_work_decode() should be called before this, since it gets preqrequisite data
   and performs basic validation of getblocktemplate request */
int lyra2Zz_gbt_work_decode(CURL *curl, const json_t* val, struct work *work);

int lyra2Zz_stratum_notify(struct stratum_ctx *sctx, json_t *params);

void lyra2Zz_assign_thread_nonce_range(int thr_id, struct work *work, uint32_t *min_nonce, uint32_t *max_nonce);

void lyra2Zz_make_header(
		lyra2zz_block_header_t *ret,
		int32_t version,
		const uint256& prev_block,
		const uint256& merkle_root,
		uint32_t time,
		uint32_t bits,
		uint64_t noncerange,	// low bits = min, 
		const uint256& accum_checkpoint,
		const uint256& target);

int lyra2Zz_benchmark_set_params(int thr_id, struct work *work);

void lyra2Zz_log_work_header(struct work * w);

void lyra2Zz_log_stratum_job(struct stratum_ctx *sctx);

extern int lyra2Zz_test_hash(int thr_id);

#ifdef __cplusplus
}
#endif

#endif // LYRA2ZZ_H_