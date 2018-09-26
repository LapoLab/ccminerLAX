#pragma once

#include "miner.h"

class crypt_random {
#ifdef _MSC_VER
	typedef HCRYPTPROV random_handle_t;
#else
	typedef void * random_handle_t;
#endif

	random_handle_t rhandle;

	bool valid; // Unspecified on windows whether or not rhandle will be NULL if there's an error, so we just use a catch all bool

public:
	crypt_random(void)
	:		rhandle(0),
			valid(false)	
	{}

	~crypt_random(void)
	{
		destroy();
	}

	void destroy(void)
	{
		if (valid) {
#ifdef _MSC_VER
			if (!CryptReleaseContext(rhandle, NULL)) {
				applog(
					LOG_ERR, 
					"%s: Problem freeing win32 handle. Error: 0x%x",
					__FUNCTION__, GetLastError()
				);
			}
#endif
			valid = false;
		}
	}

	bool init(void)
	{
#ifdef _MSC_VER
		LPCSTR cryptname = __FUNCTION__;

		if (!CryptAcquireContext(&rhandle, cryptname, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
			if (GetLastError() == (DWORD)NTE_EXISTS) {
				if (!CryptAcquireContext(&rhandle, cryptname, NULL, PROV_RSA_FULL, 0))
					goto ret_crypt_error;
			} else {
				goto ret_crypt_error;
			}
		}

		valid = true;
		return true;

	ret_crypt_error:
		applogf_fn(LOG_ERR, "Could not get windows cryptography context - error returned: 0x%x\n", GetLastError());
		return false;
#else
		applog_fn(LOG_WARNING, "Not supported on this platform.");
		return false;
#endif
	}

	bool gen_random(BYTE * adata, size_t sz)
	{
#ifdef _MSC_VER
		if (!valid) {
			applog(
				LOG_ERR, 
				"%s: Cannot randomly generate: state is invalid.",
				__FUNCTION__
			);

			return false;
		}

		if (!CryptGenRandom(rhandle, CONV_SIZE_T_TO_U32(sz), adata)) {
			applog(
				LOG_WARNING, 
				"%s: Could not randomly generate buffer for data of size %" PRIxPTR " bytes. Error: 0x%x\n", 
				__FUNCTION__ ,
				sz, GetLastError()
			);
			return false;
		}

		return true;
#else
		applog_fn(LOG_WARNING, "Not supported on this platform.");
		return false;
#endif
	}

};