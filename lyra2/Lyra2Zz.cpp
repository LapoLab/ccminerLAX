#include "Lyra2Zz.h"
#include "uint256.h"
#include "../miner.h"
extern "C" {
	#include "Lyra2Z.h"
}
#include <vector>
#include <sstream>

extern "C" int lyra2Zz_test_hash(int thr_id, uint32_t *block_data);

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

std::string reverse_hex_string(const std::string& in)
{
	std::string str_hex = in;

	size_t len = str_hex.size() >> 1;

	for (size_t i = 0; i < len; i += 2) {
		size_t j = str_hex.size() - i - 1;
		
		char tmp = str_hex[i];
		char tmp2 = str_hex[i + 1];
		
		str_hex[i + 1] = str_hex[j + 0];
		str_hex[i + 0] = str_hex[j]; 

		str_hex[j - 1] = tmp;
		str_hex[j] = tmp2;
	}

	return str_hex;
}

template <typename intType>
static bool l2zz_get_hex_str(const json_t *blocktemplate, const char *key, intType &out, bool reverse = true)
{
	std::string str_hex = l2zz_gbt_get_jstring(blocktemplate, key);
	if (str_hex.empty())
		return false;

	/* hex2bin won't accept odd-length hex strings */
	if (str_hex.size() & 0x1)
		str_hex = "0" + str_hex;

	if (reverse)
		str_hex = reverse_hex_string(str_hex);

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

	out = bits;

	return true;
}

typedef uint8_t sha256_t[32];

typedef struct l2zz_hash {
	sha256_t hash;
} l2zz_hash_t;

static l2zz_hash_t l2zz_double_sha(uint8_t *in, size_t len)
{
	l2zz_hash_t l2z1, l2z2;

	sha256d(&l2z1.hash[0], in, (int) len);
	sha256d(&l2z2.hash[0], &l2z1.hash[0], sizeof(l2z1.hash));

	return l2z2;
}

static bool l2zz_gbt_calc_merkle_root(const json_t *blocktemplate, uint256& mroot)
{
	json_t *arr_tx = json_object_get(blocktemplate, "transactions");
	size_t num_entries = 0;
	size_t index = 0;

	if (unlikely(!arr_tx))
		goto no_tx;

	if (unlikely(!json_is_array(arr_tx)))
		goto not_array;

	num_entries = json_array_size(arr_tx);

	if (unlikely(num_entries == 0))
		goto no_entries;

	{
		std::vector<l2zz_hash_t> hashes{num_entries};
		memset(&hashes[0], 0, sizeof(hashes[0]) * hashes.size());

		json_t *arr_val = nullptr;
		size_t len = 0;
		const char* data_str = nullptr;
		const register size_t sh256sz = sizeof(sha256_t);
		uint8_t concat[sh256sz << 1];
		std::vector<l2zz_hash_t> new_hashes;

		/* create first set of hashes */

		json_array_foreach(arr_tx, index, arr_val) {
			json_t *data = json_object_get(arr_val, "hash");
			std::vector<uint8_t> buff;

			if (unlikely(!json_is_string(data)))
				goto not_string;

			data_str = json_string_value(data);

			if (unlikely(!data_str))
				goto bad_string;

			len = strlen(data_str);

			if (unlikely(!len))
				goto empty_string;

			if (len & 0x1)
				len++;

			buff.resize(len >> 1);

			// NOTE: is the endianness correct here? verify in the wallet...
			//hex2bin(&buff[0], data_str, len);
			//

			hex2bin(&hashes[index].hash[0], data_str, len);

			//hashes[index] =  //l2zz_double_sha(&buff[0], buff.size());
		}

		/* build up merkle tree until we have a root hash */

		while (hashes.size() > 1) {
			if (hashes.size() & 1)
				hashes.push_back(hashes.back());
		
			new_hashes.resize(hashes.size() >> 1);

			for (size_t i = 0; i < new_hashes.size(); ++i) {
				memcpy(&concat[0], &hashes[(i << 1)].hash[0], sh256sz);
				memcpy(&concat[sh256sz], &hashes[(i << 1) + 1].hash[0], sh256sz);
				
				new_hashes[i] = l2zz_double_sha(&concat[0], sizeof(concat));
			}

			hashes = std::move(new_hashes);
		}

		memcpy(mroot.begin(), &hashes[0].hash[0], mroot.size());

		return true;
	}

no_tx:
	applog(LOG_WARNING, LYRA2ZZ_LOG_HEADER "%s", 
			"transactions entry not found...");

	return true;

not_array:
	applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", 
			"transactions entry is not an array...");

	return false;

no_entries:
	applog(LOG_WARNING, LYRA2ZZ_LOG_HEADER "%s", 
		"no entries in transactions array");
		
	return true;

not_string:
	applog(
		LOG_ERR, 
		LYRA2ZZ_LOG_HEADER "found a non-string data entry at index %ll. This is invalid, bailing...", 
		(ssize_t) index
	);

	return false;

empty_string:
	applog(
		LOG_ERR, 
		LYRA2ZZ_LOG_HEADER "found an empty data entry at index %ll. Bailing...", 
		(ssize_t) index
	);

	return false;

bad_string:
	applog(
		LOG_ERR, 
		LYRA2ZZ_LOG_HEADER "bad string returned at index %ll. Bailing...", 
		(ssize_t) index
	);

	return false;
}

static void l2zz_print_info(lyra2zz_block_header_t *header, const uint256& merkle_root, const uint256& prev_block_hash, const uint256& accum)
{
	char *m = bin2hex((const unsigned char *) merkle_root.begin(), merkle_root.size());
	char *p = bin2hex((const unsigned char *) prev_block_hash.begin(), prev_block_hash.size());
	char *a = bin2hex((const unsigned char *) accum.begin(), accum.size());
	char *b = bin2hex((const unsigned char *) &header->block_hash[0], sizeof(header->block_hash));

	std::vector<unsigned char> bhh(sizeof(header->block_hash));
	memcpy(&bhh[0], header->block_hash, sizeof(header->block_hash));
	uint256 bh{bhh};

	std::string m2 = merkle_root.GetHex();
	std::string p2 = prev_block_hash.GetHex();
	std::string a2 = accum.GetHex();
	std::string b2 = bh.GetHex();

	applog(LOG_BLUE, 
		"\n-----\n"
		"BlockHash: %s\nBlockHash_: %s\n\n"
		"Merkle Root: %s\nMerkle Root_:%s\n\n"
		"PrevBlockHash: %s\nPrevBlockHash_: %s\n\n"
		"Accum Checkpoint: %s\nAccum Checkpoint_: %s\n\n"
		"Time: %lu"
		"\n-----\n", 
		b, b2.c_str(), m, m2.c_str(), p, p2.c_str(), a, a2.c_str(), time);
			
	free(b); //free(b2);
	free(m); //free(m2);
	free(p); //free(p2);
	free(a); //free(a2);
}

void lyra2Zz_make_header(
		lyra2zz_block_header_t *ret,
		int32_t version,
		const uint256& prev_block,
		const uint256& merkle_root,
		uint32_t time,
		uint32_t bits,
		uint64_t noncerange,
		const uint256& accum_checkpoint,
		const uint256& target)
{
	memset(ret, 0, sizeof(*ret));
	
	ret->min_nonce = (uint32_t)(noncerange & 0xFFFFFFFF);
	ret->max_nonce = (uint32_t)(noncerange >> 32);

	ret->data[0] = version;
	ret->data[17] = time;
	ret->data[18] = bits;
	ret->data[19] = ret->min_nonce;

	memcpy(&ret->data[1], prev_block.begin(), prev_block.size());
	memcpy(&ret->data[9], merkle_root.begin(), merkle_root.size());
	memcpy(&ret->data[20], accum_checkpoint.begin(), accum_checkpoint.size());

	ret->data[28] = 0x80000000;
	ret->data[31] = 0x00000280;

	//uint256 target2 = uint256().SetCompact(bits);

	memcpy(&ret->target_decoded[0], target.begin(), target.size()); 

	ret->byte_view = (uint8_t *)ret->data;
}

	return ret;
}

int lyra2Zz_submit(CURL* curl, struct pool_infos *pool, struct work *work)
{
	char *str = bin2hex((uchar*)work->data, LYRA2ZZ_BLOCK_HEADER_LEN_BYTES);

	if (unlikely(!str)) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "OOM");
		return false;
	}

	/* LAPO requires a byte length prefix */
	std::stringstream stream;
    stream << std::hex << LYRA2ZZ_BLOCK_HEADER_LEN_BYTES;
    std::string hex_data( stream.str() );
	

	//std::string hex_data;
	hex_data.append(str);

	free(str);

	/* build JSON-RPC request */

	char s[4096];
	memset(s, 0, sizeof(s));

	sprintf(s,
		"{\"method\": \"submitblock\", \"params\": [\"%s\"], \"id\":10}\r\n",
		hex_data.c_str());

	/* log submit info to console */

	if (opt_debug) {
		uint32_t out[8];
		/*
		uint32_t in[28];

		for (uint32_t i = 0; i < 28; ++i)
			if (i < 27)
				in[i + 1] = work->data[i];

		in[0] = 0x70;
		*/
		lyra2Z_hash_112(out, work->data);

		char* block_hash = bin2hex((uchar*)out, sizeof(out));

		if (unlikely(!block_hash)) {
			applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "OOM");
			return false;
		}

		applog(LOG_INFO, LYRA2ZZ_LOG_HEADER "Sending the following info:\n\n"
			"Block Hash: %s\n\n"
			"Block Hex data: %s\n\n", block_hash, s);

		free(block_hash);
	}

	/* issue JSON-RPC request */
	json_t *val = json_rpc_call_pool(curl, pool, s, false, false, NULL);
	if (unlikely(!val)) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "json_rpc_call failed");
		return false;
	}

	json_decref(val);
	return true;
}

int lyra2Zz_read_getblocktemplate(const json_t *blocktemplate, lyra2zz_block_header_t *header)
{
	uint256 accum, prev_block_hash, merkle_root, target;
	uint64_t noncerange;
	int32_t version;
	uint32_t bits, time;

	if (!l2zz_gbt_get_uint256(blocktemplate, "target", target))
		return false;

	if (!l2zz_gbt_get_uint256(blocktemplate, "accumulatorcheckpoint", accum)) 
		return false;
	
	if (!l2zz_gbt_get_uint256(blocktemplate, "previousblockhash", prev_block_hash)) 
		return false;
	
	if (!l2zz_gbt_get_int(blocktemplate, "version", version)) 
		return false;
	
	if (!l2zz_gbt_get_int(blocktemplate, "curtime", time)) 
		return false;

	if (!l2zz_get_hex_str(blocktemplate, "bits", bits)) 
		return false;

	if (!l2zz_get_hex_str(blocktemplate, "noncerange", noncerange)) 
		return false;

	be32enc(&bits, bits);

	
	bool_t overflow = false;
	bool_t negative = false;

	uint256 t2;
	t2 = t2.SetCompact(bits, &overflow, &negative);

	if (target != t2) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "mismatch between bits and target after bits has been expanded");
		return false;
	}

	if (overflow) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "target overflow");
		return false;
	}

	if (negative) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "target negative");
		return false;
	}

	if (!l2zz_gbt_calc_merkle_root(blocktemplate, merkle_root)) 
		return false;

	if (header) {
		lyra2Zz_make_header(
			header,
			version, 
			prev_block_hash, 
			merkle_root, 
			time, 
			bits, 
			noncerange,
			accum,
			target
		);

		//lyra2Zz_test_hash(0, NULL);

		l2zz_print_info(header, merkle_root, prev_block_hash, accum);
	}

	return true;
}
