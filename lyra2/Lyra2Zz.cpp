#include "Lyra2Zz.h"
#include "uint256.h"
#include "../miner.h"
extern "C" {
	#include "Lyra2Z.h"
}
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>

typedef uint8_t sha256_t[32];

typedef std::vector<uint8_t> l2zz_script_t;
typedef int64_t l2zz_amount_t;

typedef struct l2zz_hash {
	sha256_t hash;
} l2zz_hash_t;

struct l2zz_outpoint {
	uint256 hash;
	uint32_t n;
};

struct l2zz_outpoint0 {
	uint256_32_t hash;
	uint32_t n;
};

struct l2zz_in0 {
	l2zz_outpoint0 prevout;
};

struct l2zz_in1 {
	uint32_t n_sequence;
};

struct l2zz_in {
	l2zz_outpoint prevout;
	l2zz_script_t script_sig;
	uint32_t n_sequence;
};

struct l2zz_out {
	l2zz_amount_t n_value;
	l2zz_script_t pub_key;
};

enum {
	    // zerocoin
    OP_ZEROCOINMINT = 0xc1,
    OP_ZEROCOINSPEND = 0xc2,
};

static bool is_script_zerocoin_mint(const l2zz_script_t& s)
{
	return !s.empty() && s.at(0) == OP_ZEROCOINMINT;
}

static bool is_script_zerocoin_spend(const l2zz_script_t& s)
{
	return !s.empty() && s.at(0) == OP_ZEROCOINSPEND;
}

static bool output_is_null(const l2zz_outpoint& p)
{
	return p.hash.IsNull() && p.n == (uint32_t)(-1);
}

struct l2zz_transaction {
	int32_t n_version;
	std::vector<l2zz_in> in;
	std::vector<l2zz_out> out;
	uint32_t n_lock_time;

	bool zerocoin_mint(void) const
	{
		for (const l2zz_out& o: out) {
			if (is_script_zerocoin_mint(o.pub_key))
				return true;
		}

		return false;
	}

	bool zerocoin_spend(void) const
	{
		return !in.empty() 
			&& output_is_null(in.at(0).prevout) 
			&& is_script_zerocoin_spend(in.at(0).script_sig);
	}

	bool has_zerocoins(void) const
	{
		return zerocoin_mint() || zerocoin_spend();
	}

	bool coinbase(void) const
	{
		return in.size() == 1 
			&& output_is_null(in.at(0).prevout)
			&& !has_zerocoins();
	}
};

typedef struct l2zz_header_helper {
	int32_t version;
	uint256_32_t prev_block;
	uint256_32_t merkle_root;
	uint32_t time;
	uint32_t bits;
	uint32_t nonce;
	uint256_32_t accum_checkpoint;

} l2zz_header_helper_t;



static void make_u256(uint256_32_t in, uint256& out)
{
	std::vector<unsigned char> tmp(32);
	memcpy(&tmp[0], &in[0], 32);
	out = uint256(tmp);
}

static std::string get_hexb(uint8_t x)
{
	std::stringstream ss;
	ss << std::setfill('0') << std::setw(2) << std::hex << (uint16_t)x;
	return ss.str();
}

static std::string get_hex_bytes(uint32_t x)
{
	uint8_t *p = (uint8_t*)&x;
	
	std::stringstream ss;

	ss << get_hexb(p[0]);
	ss << get_hexb(p[1]);
	ss << get_hexb(p[2]);
	ss << get_hexb(p[3]);

	std::string ret = ss.str();

	return ret;
}

static std::string get_hex_bytes(uint256_32_t x)
{
	std::stringstream ss;

	for (size_t i = 0; i < 8; ++i)
		ss << get_hex_bytes(x[i]);

	return ss.str();
}

class l2zz_internal_data {
public:
	std::vector<std::vector<uint8_t>> transactions;
	std::vector<l2zz_transaction> tx_decoded;
	size_t coinbase_index;

	/*
	struct compact_size {
		union variant {
			uint8_t u8;
			uint16_t u16;
			uint32_t u32;
			uint64_t 
		};
	}
	*/

	l2zz_internal_data(void) 
		: coinbase_index(0)
	{}

	uint8_t * read_compact_size(size_t& value, uint8_t *p)
	{
		size_t b1 = (size_t)(*p);

		if (b1 <= 252) {
			value = b1;
			return p + 1;
		} else if (b1 == 253) {
			uint16_t k;
			p = read_data(k, p);
			value = k;
		} else if (b1 == 254) {			
			uint32_t k;
			p = read_data(k, p);
			value = k;
		} else {
			uint64_t k;
			p = read_data(k, p);
			value = k;
		}

		return p;
	}

	template <class dataType>
	uint8_t * read_data(dataType& value, uint8_t * p)
	{
		value = *((dataType *)p);
		return p + sizeof(dataType);
	}

	uint8_t * read_buffer(std::vector<uint8_t>& buffer, uint8_t *p)
	{
		size_t buff_size;

		p = read_compact_size(buff_size, p);
		buffer.resize(buff_size);

		if (!buffer.empty()) {
			memcpy(&buffer[0], p, buff_size);
		}

		return p + buff_size;
	}

	void decode_transaction(std::vector<uint8_t>& tx)
	{
		l2zz_transaction decoded;

		uint8_t *p = tx.data();

		p = read_data(decoded.n_version, p);

		size_t in_count;
		p = read_compact_size(in_count, p);

		for (size_t i = 0; i < in_count; ++i) {
			l2zz_in in;
			
			uint256_32_t hash;
			memcpy(&hash[0], p, sizeof(hash));
			p += sizeof(hash);

			p = read_data(in.prevout.n, p);
			
			p = read_buffer(in.script_sig, p);
			p = read_data(in.n_sequence, p);

			decoded.in.push_back(in);
		}

		size_t out_count;
		p = read_compact_size(out_count, p);

		for (size_t i = 0; i < out_count; ++i) {
			l2zz_out out;

			p = read_data(out.n_value, p);
			p = read_buffer(out.pub_key, p);
		}

		p = read_data(decoded.n_lock_time, p);

		if (decoded.coinbase()) {
			coinbase_index = tx_decoded.size();
		}

		tx_decoded.push_back(decoded);
	}

	void reset(void) {
		transactions.clear();
		tx_decoded.clear();
	}
};

static std::unique_ptr<l2zz_internal_data> g_internal_data(new l2zz_internal_data());

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
		str_hex[i + 0] = str_hex[j - 1]; 

		str_hex[j - 1] = tmp;
		str_hex[j + 0] = tmp2;
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



static l2zz_hash_t l2zz_double_sha(uint8_t *in, size_t len)
{
	l2zz_hash_t l2z1;

	/* d stands for "double" and not "default" */
	sha256d(&l2z1.hash[0], in, (int) len);

	return l2z1;
}

#define l2zz_parse_transact(name) \
		json_t *t_##name = json_object_get(arr_val, #name);			\
																	\
		if (unlikely(!json_is_string(t_##name)))					\
			goto not_string;										\
																	\
		const char *t_##name##_str = json_string_value(t_##name);	\
																	\
		if (unlikely(!t_##name##_str))								\
			goto bad_string;										\
																	\
		size_t t_len = strlen(t_##name##_str);						\
																	\
		if (unlikely(!t_len))										\
			goto empty_string;										\
																	\
		if (t_len & 0x1)											\
			t_len++	

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
			/* hash hex encoded transaction data */
			l2zz_parse_transact(data);

			std::vector<uint8_t> buff;
			buff.resize(t_len >> 1);

			hex2bin(&buff[0], t_data_str, t_len >> 1);

			hashes[index] = l2zz_double_sha(&buff[0], buff.size());

			g_internal_data->decode_transaction(buff);

			/* keep track of the data so we can send it over the wire */
			g_internal_data->transactions.push_back(std::move(buff));
		}

		/* merkle root is just hash/id of coinbase transaction if all we have is the coinbase */
		if (num_entries == 1) {
			memcpy(mroot.begin(), &hashes[0].hash[0], mroot.size());
			return true;
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
	applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", 
		"no entries in transactions array");
		
	return false;

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

#undef l2zz_parse_transact

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

	memcpy(&ret->target_decoded[0], target.begin(), target.size()); 

	ret->byte_view = (uint8_t *)ret->data;
}



int lyra2Zz_submit(CURL* curl, struct pool_infos *pool, struct work *work)
{
	/* serialize the header data */

	uint32_t *pdata = work->data;

	l2zz_header_helper_t *header = (l2zz_header_helper_t *)(pdata);

	uint256 prev, merkle, accum;

	make_u256(header->prev_block, prev);
	make_u256(header->merkle_root, merkle);
	make_u256(header->accum_checkpoint, accum);

	uint256 target = uint256().SetCompact(header->bits);
	std::string strtarget = target.GetHex();

	std::stringstream hex_data_stream;

	std::string str_time, str_bits, str_nonce, str_ver;

	be32enc(&header->nonce, header->nonce);

	str_time = get_hex_bytes(header->time);
	str_bits = get_hex_bytes(header->bits);
	str_nonce = get_hex_bytes(header->nonce);
	str_ver = get_hex_bytes(header->version);

	/* header data */
	hex_data_stream << str_ver;
	hex_data_stream << get_hex_bytes(header->prev_block);
	hex_data_stream << get_hex_bytes(header->merkle_root);
	hex_data_stream << str_time;
	hex_data_stream << str_bits;
	hex_data_stream << str_nonce;
	hex_data_stream << get_hex_bytes(header->accum_checkpoint);
	
	/* transactions */

	size_t num_trans = g_internal_data->transactions.size() & 0xFF;

	hex_data_stream << get_hexb((uint8_t) num_trans);

	for (size_t i = 0; i < g_internal_data->transactions.size(); ++i) {
		char *encoded_t = bin2hex(
			(const unsigned char *)g_internal_data->transactions[i].data(),  
			g_internal_data->transactions[i].size());

		hex_data_stream << encoded_t;

		free(encoded_t);
	}

	hex_data_stream << "00"; // signature size

	/* build JSON-RPC request */

	std::string hex_data = hex_data_stream.str();

	std::vector<char> s(4096 + hex_data.size());
	memset(&s[0], 0, s.size());

	sprintf(&s[0],
		"{\"method\": \"submitblock\", \"params\": [\"%s\"], \"id\":10}\r\n",
		hex_data.c_str());

	// make u256 block hash for client side tests
	uint32_t out[8];		
	lyra2Z_hash_112(out, pdata);

	uint256 block_hash;
	make_u256(&out[0], block_hash);

	/* log submit info to console */

	header = (l2zz_header_helper_t *)work->data;
	target = uint256().SetCompact(header->bits);

	if (opt_debug) {
		std::string str_block_hash = block_hash.GetHex();
		std::string str_target = target.GetHex();

		applog(LOG_INFO, LYRA2ZZ_LOG_HEADER "Sending the following info:\n\n"
			"HEx Char Length: %i\n\n"
			"Block Hash: %s\n\n"
			"Target: %s\n\n"
			"Block Hex data: %s\n\n", 
			hex_data.size(), 
			str_block_hash.c_str(),
			str_target.c_str(),
			s.data());
	}

	/* one final check */
	if (target < block_hash) {
		std::string str_block_hash = block_hash.GetHex();
		std::string str_target = target.GetHex();
		applog(LOG_ERR, 
			LYRA2ZZ_LOG_HEADER "block hash %s > target %s", str_block_hash.c_str(),
			str_target.c_str());

		return false;
	}

	/* issue JSON-RPC request */
	json_t *val = json_rpc_call_pool(curl, pool, s.data(), false, false, NULL);
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

	/* clear out previous block info */
	g_internal_data->reset();

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

	if (!l2zz_get_hex_str(blocktemplate, "noncerange", noncerange, false)) 
		return false;
	
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
