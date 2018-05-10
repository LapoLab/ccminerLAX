#include "Lyra2Zz.h"
#include "uint256.h"
#include "../miner.h"
#include "../elist.h"
#include "Lyra2Z.h"

static inline std::string l2zz_gbt_get_jstring(const json_t* blocktemplate, const char* key)
{
	json_t *val = json_object_get(blocktemplate, key);

	const char* str = nullptr;

	if (!val || !(str = json_string_value(val))) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "bad %s in getblocktemplate: %s", key, (!val ? "entry not found" : "value isn't a string"));
		return std::string{""};
	}

	return std::string{str};
}

static inline json_int_t l2zz_gbt_get_jint(const json_t* blocktemplate, const char* key)
{
	json_t *val = json_object_get(blocktemplate, key);

	if (!val) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "bad %s in getblocktemplate: entry not found.", key);
		return -1; 
	}

	return json_integer_value(val);
}

template <typename intType>
static bool l2zz_gbt_get_int(const json_t *blocktemplate, const char *key, intType &val) 
{
	val = (intType) l2zz_gbt_get_jint(blocktemplate, key);									
	if (!val || val == -1) {																	
		if (!val) {																			
			applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "bad %s = %i in getblocktemplate", key, val);	
		}																						
		return false;																			
	}

	return true;
}


static bool l2zz_gbt_get_uint256(const json_t *blocktemplate, const char *key, uint256 &out)
{
	std::string str = l2zz_gbt_get_jstring(blocktemplate, key);	
	if (str.empty())												
		return false;													
	
	out = uint256{str};

	return true;
}

lyra2zz_block_header_t lyra2zz_make_header(
		int32_t version,
		const uint256& prev_block,
		const uint256& merkle_root,
		uint32_t time,
		uint32_t bits,
		uint32_t nonce,
		const uint256& accum_checkpoint)
{
	lyra2zz_block_header_t ret;

	memset(&ret, 0, sizeof(ret));
	
	ret.data[0] = version;
	ret.data[17] = time;
	ret.data[18] = bits;
	ret.data[19] = nonce;

	memcpy(&ret.data[1], prev_block.begin(), prev_block.size());
	memcpy(&ret.data[9], merkle_root.begin(), merkle_root.size());
	memcpy(&ret.data[20], accum_checkpoint.begin(), accum_checkpoint.size());

	ret.data[28] = 0x80000000;
	ret.data[31] = 0x00000280;

	return ret;
}

template <typename intType>
static bool l2zz_get_hex_str(const json_t *blocktemplate, const char *key, intType &out)
{
	std::string str_hex = l2zz_gbt_get_jstring(blocktemplate, key);
	if (str_hex.empty())
		return false;

	/* hex2bin won't accept odd-length hex strings */
	if (str_hex.size() & 0x1)
		str_hex = "0" + str_hex;


	if ((str_hex.size() >> 1) > sizeof(out)) {
		applog(LOG_ERR, 
			LYRA2ZZ_LOG_HEADER "%s char length requires %ll "
			"which is too large. hex string received: %s",
			key,
			str_hex.size() >> 1,
			str_hex.c_str());
		return false;
	}
	
	intType bits;
	if (!hex2bin(&bits, str_hex.c_str(), str_hex.size() >> 1)) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "could not parse hex string for %s...", key);
		return false;
	}

	return true;
}

int lyra2zz_read_getblocktemplate(const json_t *blocktemplate, lyra2zz_block_header_t *header)
{
	uint256 accum, prev_block_hash, merkle_root;
	uint64_t noncerange;
	int32_t version;
	uint32_t bits, time;

	if (!l2zz_gbt_get_uint256(blocktemplate, "accumulatorcheckpoint", accum)) return false;
	if (!l2zz_gbt_get_uint256(blocktemplate, "previousblockhash", prev_block_hash)) return false;
	
	if (!l2zz_gbt_get_int(blocktemplate, "version", version)) return false;
	if (!l2zz_gbt_get_int(blocktemplate, "curtime", time)) return false;

	if (!l2zz_get_hex_str(blocktemplate, "bits", bits)) return false;

	if (!l2zz_get_hex_str(blocktemplate, "noncerange", noncerange)) return false;

	// TODO: calculate merkle_root

	if (header) {
		*header = lyra2zz_make_header(
			version, 
			prev_block_hash, 
			merkle_root, 
			time, bits, 
			(uint32_t)(noncerange & 0xFFFFFFFF),
			accum
		);
	}

	return true;
}

int lyra2z_test_blake_80(void)
{
	return 0;
}