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

#include "../sph/sph_sha2.h"

#include "libbase58.h"

static inline std::string l2zz_gbt_get_jstring(const json_t* blocktemplate, const char* key);
static inline json_int_t l2zz_gbt_get_jint(const json_t* blocktemplate, const char* key);

template <typename intType>
static bool l2zz_gbt_get_int(const json_t *blocktemplate, const char *key, intType &val);

static bool l2zz_gbt_get_uint256(const json_t *blocktemplate, const char *key, uint256 &out);

template <typename intType>
static bool l2zz_get_hex_str(const json_t *blocktemplate, const char *key, intType &out, bool reverse = true);

static void l2zz_dump_json(const char*tag, const json_t *obj)
{
	char *s = json_dumps(obj, JSON_ENCODE_ANY);
	applog(LOG_DEBUG, LYRA2ZZ_LOG_HEADER "[%s] json: %s", tag, s);
	free(s);
}

#define l2zz_align8(sz) ((sz + 7) & (~7))

static bool l2zz_b58_sha256(void *digest, const void *data, size_t datasz)
{
	sph_sha256_context ctx;
	sph_sha256_init(&ctx);
	sph_sha256(&ctx, data, datasz);
	sph_sha256_close(&ctx, digest);

	return true;
}

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

struct l2zz_in {
	l2zz_outpoint prevout;
	l2zz_script_t script_sig;
	uint32_t n_sequence;
};

struct l2zz_out {
	l2zz_amount_t n_value;
	l2zz_script_t pub_key;
};

/** Script opcodes */
enum
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // zerocoin
    OP_ZEROCOINMINT = 0xc1,
    OP_ZEROCOINSPEND = 0xc2,

    // template matching params
    OP_SMALLINTEGER = 0xfa,
    OP_PUBKEYS = 0xfb,
    OP_PUBKEYHASH = 0xfd,
    OP_PUBKEY = 0xfe,

    OP_INVALIDOPCODE = 0xff,
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
		const bool a = !in.empty();
		const bool b = output_is_null(in.at(0).prevout);
		const bool c = is_script_zerocoin_spend(in.at(0).script_sig);

		return a && b && c;
	}

	bool has_zerocoins(void) const
	{
		const bool a = zerocoin_mint();
		const bool b = zerocoin_spend();
		return a || b;
	}

	bool coinbase(void) const
	{
		const bool a = in.size() == 1;
		const bool b = output_is_null(in.at(0).prevout);
		const bool c = !has_zerocoins();
	
		return a && b && c;
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

/* these are solely for coinbase generation */
static const size_t l2zz_pubkey_script_size = 25;
static const size_t l2zz_output_size = sizeof(l2zz_amount_t) + 1 + l2zz_pubkey_script_size;
static const size_t l2zz_coinbase_size = 54 + 2 * l2zz_output_size; 

class l2zz_internal_data {
public:
	std::vector<std::vector<uint8_t>> transactions;
	std::vector<l2zz_transaction> tx_decoded;
	std::string masternode_pubkey;
	std::string rawchange_pubkey;
	
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

	uint8_t * cb_write_output(
		uint8_t *data, 
		uint8_t *script, 
		size_t scriptsz, 
		l2zz_amount_t cb_value,
		size_t output_sz)
	{
		for (size_t i = 0; i < sizeof(cb_value); ++i) 
			data[i] = (cb_value >> (8 * i)) & 0xff;

		if (scriptsz > 255) 
			applog(LOG_WARNING, 
				LYRA2ZZ_LOG_HEADER "scriptsz received with size > 255. This isn't supported yet. Size: %l", 
				scriptsz);

		data[sizeof(cb_value)] = (uint8_t) scriptsz;
		
		if (scriptsz)
			memcpy(&data[sizeof(cb_value) + 1], script, scriptsz);

		return data + output_sz;
	}

	/* adapted from https://raw.githubusercontent.com/bitcoin/libblkmaker/master/base58.c */
	size_t address_to_script(uint8_t *out, size_t outsz, const char *addr) {
		unsigned char addrbin[25];

		unsigned char *cout = (unsigned char *) out;
		const size_t b58sz = strlen(addr);
		int addrver;
		size_t rv;
	
		rv = sizeof(addrbin);
		if (!b58_sha256_impl)
			b58_sha256_impl = l2zz_b58_sha256;
		if (!b58tobin(addrbin, &rv, addr, b58sz))
			return 0;
		addrver = b58check(addrbin, sizeof(addrbin), addr, b58sz);
		switch (addrver) {
			case   0:	// Bitcoin pubkey hash
			case 111:	// Testnet pubkey hash
			case 109:	// LAPO Testnet (?) pubkey hash
				if (outsz < (rv = 25))
					return rv;
				cout[ 0] = 0x76;  // OP_DUP
				cout[ 1] = 0xa9;  // OP_HASH160
				cout[ 2] = 0x14;  // push 20 bytes
				memcpy(&cout[3], &addrbin[1], 20);
				cout[23] = 0x88;  // OP_EQUALVERIFY
				cout[24] = 0xac;  // OP_CHECKSIG

				return rv;
			case   5:  // Bitcoin script hash
			case 196:  // Testnet script hash
				if (outsz < (rv = 23))
					return rv;
				cout[ 0] = 0xa9;  // OP_HASH160
				cout[ 1] = 0x14;  // push 20 bytes
				memcpy(&cout[2], &addrbin[1], 20);
				cout[22] = 0x87;  // OP_EQUAL
				return rv;
			default:
				return 0;
		}
	}

	bool make_coinbase(const json_t *blocktemplate, sha256_t hash)
	{	
		uint8_t script_masternode[l2zz_pubkey_script_size];
		memset(&script_masternode[0], 0, sizeof(script_masternode));
		
		if (!address_to_script(&script_masternode[0], l2zz_pubkey_script_size, masternode_pubkey.c_str())) 
			return false;

		uint8_t script_rawchange[l2zz_pubkey_script_size];
		memset(&script_rawchange[0], 0, sizeof(script_rawchange));

		if (!address_to_script(&script_rawchange[0], l2zz_pubkey_script_size, rawchange_pubkey.c_str()))
			return false;

		std::vector<uint8_t> cb_buffer;

		cb_buffer.resize(l2zz_coinbase_size, 0);

		uint8_t *data = &cb_buffer[0];

		/* the following is adapted from https://github.com/bitcoin/libblkmaker/blob/master/blkmaker.c#L189 */
		size_t off = 0;

		if (!data)
			return 0;
	
		memcpy(&data[0],
			"\x01\0\0\0"  /* txn ver */
 			"\x01"        /* input count */
				"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"  /* outpoint prevout */
				"\xff\xff\xff\xff"  /* outpoint index (-1) */
				"\x02"              /* scriptSig length */
			, 42);

		off += 43;

		/* height data push script */
		{
			uint32_t h = 0;
		
			if (!l2zz_gbt_get_int(blocktemplate, "height", h)) {
				applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "could not get block height");
				return false;
			}

			while (h > 127) {
				++data[41];
				data[off++] = h & 0xff;
				h >>= 8;
			}

			data[off++] = h;
		}

		data[42] = data[41] - 1; /* Push <height serialization length> bytes OPCODE */

		memcpy(
			&data[off],
			"\xff\xff\xff\xff"  /* sequence */
			"\x02",				/* output count */
			5
		);
		
		off += 5;

		data = &cb_buffer[off];

		/* provide masternode reward  */
		l2zz_amount_t payee_value = 0;
		{
			if (!l2zz_gbt_get_int(blocktemplate, "payee_amount", payee_value)) {
				applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "could not get payee amount");
				return false;
			}

			data = cb_write_output(
				data, 
				script_masternode, 
				l2zz_pubkey_script_size, 
				payee_value, 
				l2zz_output_size
			);
		}
		
		/* set host reward (whoever is running this miner) */
		{
			l2zz_amount_t cb_value = 0;
			
			if (!l2zz_gbt_get_int(blocktemplate, "coinbasevalue", cb_value)) {
				applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "could not get coinbase value");
				return false;
			}

			data = cb_write_output(
				data, 
				script_rawchange, 
				l2zz_pubkey_script_size, 
				cb_value - payee_value, 
				l2zz_output_size
			);
		}

		memset(data, 0, 4);  /* lock time */
		data += 4;

		sha256d(
			(unsigned char*) &hash[0], 
			(const unsigned char *)cb_buffer.data(), 
			(int) cb_buffer.size()
		);

		transactions.insert(transactions.begin(), cb_buffer);

		return true;
	}

	void decode_transaction(std::vector<uint8_t>& tx, size_t index)
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

		tx_decoded.push_back(decoded);
	}

	void reset(void) {
		masternode_pubkey = "";
		transactions.clear();
		tx_decoded.clear();
	}
};

static pthread_mutex_t g_internal_mut = PTHREAD_MUTEX_INITIALIZER;
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
static bool l2zz_get_hex_str(const json_t *blocktemplate, const char *key, intType &out, bool reverse)
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

	{
		std::vector<l2zz_hash_t> hashes{num_entries + 1};
		memset(&hashes[0], 0, sizeof(hashes[0]) * hashes.size());
	
		if (unlikely(!g_internal_data->make_coinbase(blocktemplate, hashes[0].hash)))
			return false;

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

			/* add 1 to account for coinbase */
			l2zz_hash_t h = l2zz_double_sha(&buff[0], buff.size());

			memcpy(&hashes[index + 1].hash[0], &h.hash[0], sizeof(h.hash));

			/* keep track of the data so we can send it over the wire */
			g_internal_data->transactions.push_back(buff);
		}

		/* merkle root is just hash/id of coinbase transaction if all we have is the coinbase */
		if (num_entries == 1) {
			memcpy(mroot.begin(), &hashes[0].hash[0], mroot.size());
			return true;
		}

		/* build up merkle tree until we have a root hash */
		while (hashes.size() > 1) {		
			new_hashes.resize((hashes.size() + 1) >> 1);

			for (size_t i = 0; i < new_hashes.size(); ++i) {
				size_t j = min((i << 1) + 1, hashes.size() - 1);

				memcpy(&concat[0], &hashes[(i << 1)].hash[0], sh256sz);
				memcpy(&concat[sh256sz], &hashes[j].hash[0], sh256sz);
				
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

	char* encoding = bin2hex((uchar *)header->byte_view, 112); 
	size_t len = strlen(encoding);

	std::string m2 = merkle_root.GetHex();
	std::string p2 = prev_block_hash.GetHex();
	std::string a2 = accum.GetHex();

	applog(LOG_BLUE, 
		"\n-----\n"
		"Encoding (%i): %s\n\n"
		"Merkle Root: %s\nMerkle Root_:%s\n\n"
		"PrevBlockHash: %s\nPrevBlockHash_: %s\n\n"
		"Accum Checkpoint: %s\nAccum Checkpoint_: %s\n\n"
		"Time: %lu"
		"\n-----\n", 
		len,
		encoding,
		m, m2.c_str(), p, p2.c_str(), a, a2.c_str(), time);
			
	free(encoding);
	free(m); //free(m2);
	free(p); //free(p2);
	free(a); //free(a2);
}

static bool lyra2Zz_read_getblocktemplate(const json_t *blocktemplate, lyra2zz_block_header_t *header)
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

static json_t * l2zz_exec_read_cmd(CURL *curl, const char *cmd, struct work *work)
{
	struct pool_infos *pool = &pools[work->pooln];

	int curl_err = 0;
	json_t *val = json_rpc_call_pool(curl, pool, cmd, false, false, &curl_err);
	
	if (curl_err || !val) {
		applog(LOG_ERR, 
			LYRA2ZZ_LOG_HEADER 
			"RPC call error. error code retuned: %i; cmd:\n%s", 
			curl_err, cmd);

		return NULL;
	}

	//l2zz_dump_json(cmd, val); 

	json_t *result = json_object_get(val, "result");

	if (!result) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "no result returned from cmd: %s\n", cmd);
		return NULL;
	}

	return result;
}

static bool l2zz_gbt_get_transact_info(CURL *curl, struct work *work)
{
	{
		const char *masternode_cmd = "{\"method\": \"masternodecurrent\", \"params\": [],"
				" \"id\":9}\r\n";
	
		json_t *result = l2zz_exec_read_cmd(curl, masternode_cmd, work);

		g_internal_data->masternode_pubkey = l2zz_gbt_get_jstring(result, "pubkey");

		if (g_internal_data->masternode_pubkey.empty()) {
			applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "no masternode pubkey found");
			return false;
		}
	}

	{
		const char *rawchangeaddress_cmd = "{\"method\": \"getrawchangeaddress\", \"params\": [],"
				" \"id\":9}\r\n";

		json_t *result = l2zz_exec_read_cmd(curl, rawchangeaddress_cmd, work);

		g_internal_data->rawchange_pubkey = std::string(json_string_value(result));

		if (g_internal_data->rawchange_pubkey.empty()) {
			applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "no rawchange pubkey found");
			return false;
		}
	}

	return true;
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
		/* 
			we're in a loop; we could forgoe allocation by using a larger buffer 
			and only referring to what's necessary (and reallocing if needed). 
			That's probably more efficient. For now this works
		*/

		const size_t max_stack_bytes = 4096;
		size_t hex_len = g_internal_data->transactions.size() << 1;

		char *encoded_t = hex_len < max_stack_bytes 
			? (char *)_alloca(hex_len + 1)
			: (char *)malloc(hex_len + 1);
		
		if (unlikely(hex_len >= max_stack_bytes && !encoded_t)) {
			applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "OOM");
			return false;
		}

		memset(encoded_t, 0, hex_len + 1);

		cbin2hex(
			&encoded_t[0],
			(const char *) g_internal_data->transactions[i].data(), 
			g_internal_data->transactions[i].size()
		);

		hex_data_stream << encoded_t;

#ifdef _DEBUG
		applog(
			LOG_DEBUG, 
			"Transaction [%i, %i]: %s", 
			i,
			g_internal_data->transactions[i].size(), encoded_t
		);
#endif

		if (unlikely(hex_len >= max_stack_bytes))
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

		goto fail;
	}

	/* issue JSON-RPC request */
	json_t *val = json_rpc_call_pool(curl, pool, s.data(), false, false, NULL);
	if (unlikely(!val)) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "json_rpc_call failed");
		
		goto fail;
	}

	json_decref(val);

	return true;

fail:
	return false;
}

int lyra2Zz_gbt_work_decode(CURL *curl, const json_t *val, struct work *work)
{
	g_internal_data->reset();

	if (!val) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "received null json result");
		return false;
	}

	if (!curl) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "received null curl param");
		return false;
	}

	if (!work) {
		applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "%s", "received null work param");
		return false;
	}

	/* get necessary masternode information */
	
	if (!l2zz_gbt_get_transact_info(curl, work))
		return false;

	lyra2zz_block_header_t header;

	if (!lyra2Zz_read_getblocktemplate(val, &header))
		return false;

	work->noncerange.u32[0] = header.min_nonce;
	work->noncerange.u32[1] = header.max_nonce;

	memcpy(&work->target[0], &header.target_decoded[0], sizeof(header.target_decoded));
	memcpy(&work->data[0], &header.data[0],	LYRA2ZZ_BLOCK_HEADER_LEN_BYTES);

	return true;
}
