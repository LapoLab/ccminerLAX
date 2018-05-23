#ifndef LYRA2ZZ_H_
#define LYRA2ZZ_H_

#include <stdint.h>
#include "curl\curl.h"

#define LYRA2ZZ_BLOCK_HEADER_LEN_BYTES 112
#define LYRA2ZZ_BLOCK_HEADER_NONCE_OFFSET 19 /* 19 * 4 bytes */

#define LYRA2ZZ_BLOCK_HEADER_UINT32_LEN 32

#define LYRA2ZZ_LOG_HEADER __func__ " lyra2zz - "

typedef uint32_t uint256_32_t[8];

typedef struct lyra2zz_block_header {
	uint256_32_t block_hash;
	uint256_32_t target_decoded;
	uint32_t min_nonce;
	uint32_t max_nonce;
	uint32_t data[LYRA2ZZ_BLOCK_HEADER_UINT32_LEN];
} lyra2zz_block_header_t;

class uint256;
struct json_t;

/* this only returns a bool, but because uint256 is required there's too much macro redefinition 
   conflict issues that occur if stdbool is included here, as well as if bool is declared: its type in the 
   source file gets overriden by the macro definition. */
int lyra2Zz_read_getblocktemplate(const json_t* blocktemplate, lyra2zz_block_header_t *out_header);

int lyra2Zz_submit(CURL *curl, struct pool_infos *pools, struct work *work);

lyra2zz_block_header_t lyra2Zz_make_header(
		int32_t version,
		const uint256& prev_block,
		const uint256& merkle_root,
		uint32_t time,
		uint32_t bits,
		uint64_t noncerange,	// low bits = min, 
		const uint256& accum_checkpoint,
		const uint256& target);

#endif // LYRA2ZZ_H_