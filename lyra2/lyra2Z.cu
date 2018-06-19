#include "uint256.h"

extern "C" {
#include <sph/sph_blake.h>
#include "Lyra2Z.h"
}

#include <miner.h>
#include <cuda_helper.h>

static uint64_t* d_hash[MAX_GPUS];
static uint64_t* d_matrix[MAX_GPUS];

extern void blake256_cpu_init(int thr_id, uint32_t threads);
extern void blake256_cpu_hash_80(const int thr_id, const uint32_t threads, const uint32_t startNonce, uint64_t *Hash, int order);
extern void blake256_cpu_setBlock_80(uint32_t *pdata);

extern void blake256_cpu_hash_112(const int thr_id, const uint32_t threads, const uint32_t startNonce, uint64_t *Hash, int order);
extern void blake256_cpu_setBlock_112(uint32_t *pdata);

extern void lyra2Z_cpu_init(int thr_id, uint32_t threads, uint64_t *d_matrix);
extern void lyra2Z_cpu_init_sm2(int thr_id, uint32_t threads);
extern void lyra2Z_cpu_free(int thr_id);
extern uint32_t lyra2Z_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNonce, uint64_t *d_outputHash, bool gtx750ti);

extern void lyra2Z_setTarget(const void *ptarget);
extern uint32_t lyra2Z_getSecNonce(int thr_id, int num);

extern void lyra2Zz_cpu_init(int thr_id, uint32_t threads, uint64_t *d_matrix);
extern void lyra2Zz_cpu_init_sm2(int thr_id, uint32_t threads);
extern void lyra2Zz_cpu_free(int thr_id);
extern uint32_t lyra2Zz_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNonce, uint64_t *d_outputHash, bool gtx750ti);

extern void lyra2Zz_setTarget(const void *ptarget);
extern uint32_t lyra2Zz_getSecNonce(int thr_id, int num);
/*
extern "C" void lyra2Z_hash(void *state, const void *input)
{
	uint32_t _ALIGN(64) hashA[8], hashB[8];
	sph_blake256_context ctx_blake;

	sph_blake256_set_rounds(14);
	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hashA);

	LYRA2Z(hashB, 32, hashA, 32, hashA, 32, 8, 8, 8);

	memcpy(state, hashB, 32);
}

extern "C" void lyra2Z_hash_112(void *state, const void *input)
{
	uint32_t _ALIGN(64) hashA[8], hashB[8];
	sph_blake256_context ctx_blake;

	sph_blake256_set_rounds(14);
	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 112);
	sph_blake256_close(&ctx_blake, hashA);

	LYRA2Z(hashB, 32, hashA, 32, hashA, 32, 8, 8, 8);

	memcpy(state, hashB, 32);
}
*/

static bool init[MAX_GPUS] = { 0 };
static __thread uint32_t throughput = 0;
static __thread bool gtx750ti = false;
static __thread size_t d_matrix_size = 0;

static size_t d_hash_size_bytes() 
{ 
	return (size_t)32 * throughput; 
}

static void maybe_init_thread_data(int thr_id, int dev_id, uint32_t max_nonce, uint32_t first_nonce)
{
	if (init[thr_id])
		return;

	cudaSetDevice(dev_id);
	if (opt_cudaschedule == -1 && gpu_threads == 1) {
		cudaDeviceReset();
		cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
		CUDA_LOG_ERROR();
	}

	cuda_get_arch(thr_id);
	int intensity = (device_sm[dev_id] > 500 && !is_windows()) ? 17 : 16;
	if (device_sm[dev_id] <= 500) intensity = 15;
	throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
	if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

	cudaDeviceProp props;
	cudaGetDeviceProperties(&props, dev_id);
	gtx750ti = (strstr(props.name, "750 Ti") != NULL);

	gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

	blake256_cpu_init(thr_id, throughput);

	if (device_sm[dev_id] >= 350)
	{
		size_t matrix_sz = device_sm[dev_id] > 500 ? sizeof(uint64_t) * 4 * 4 : sizeof(uint64_t) * 8 * 8 * 3 * 4;
		d_matrix_size = matrix_sz;
		CUDA_SAFE_CALL(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput));
		lyra2Zz_cpu_init(thr_id, throughput, d_matrix[thr_id]);
	}
	else
		lyra2Zz_cpu_init_sm2(thr_id, throughput);

	CUDA_SAFE_CALL(cudaMalloc(&d_hash[thr_id], d_hash_size_bytes()));

	init[thr_id] = true;
}

struct target_hash {
	uint32_t target;
	uint32_t vhash;
	uint32_t nonce_ret;
	uint32_t first_nonce;
};

static std::vector<target_hash> g_targethash;

static bool nonce_already_been_reported(uint32_t target, uint32_t vhash, uint32_t nonce_ret, uint32_t first_nonce)
{
	target_hash x;
	x.target = target;
	x.vhash = vhash;
	x.nonce_ret = nonce_ret;
	x.first_nonce = first_nonce;

	for (size_t i = 0; i < g_targethash.size(); ++i) {
		if (!memcmp(&x, &g_targethash[i], sizeof(x)))
			return true;
	}

	g_targethash.push_back(x);

	return false;
}

static void maybe_report_bad_nonce(int thr_id, uint32_t target, uint32_t vhash, uint32_t nonce_ret, uint32_t first_nonce)
{
	if (nonce_already_been_reported(target, vhash, nonce_ret, first_nonce))
		return;

	if (!opt_quiet)	gpulog(LOG_WARNING, thr_id,
					"\nfirst_nonce = %08x\n"
					"target high word = %08x\n"
					"GPU nonce found = %08x\n"
					"vhash high word = %08x\n"
					"result does not validate on CPU!\n",
					first_nonce, target, nonce_ret, vhash);
}

extern "C" int scanhash_lyra2Z(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	int dev_id = device_map[thr_id];

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

	applog(LOG_BLUE, "Device shader model: %i", device_sm[thr_id % MAX_GPUS]);

	if (!init[thr_id])
	{
		cudaSetDevice(dev_id);
		if (opt_cudaschedule == -1 && gpu_threads == 1) {
			cudaDeviceReset();
			cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
			CUDA_LOG_ERROR();
		}

		cuda_get_arch(thr_id);
		int intensity = (device_sm[dev_id] > 500 && !is_windows()) ? 17 : 16;
		if (device_sm[dev_id] <= 500) intensity = 15;
		throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
		if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

		cudaDeviceProp props;
		cudaGetDeviceProperties(&props, dev_id);
		gtx750ti = (strstr(props.name, "750 Ti") != NULL);

		gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

		blake256_cpu_init(thr_id, throughput);

		if (device_sm[dev_id] >= 350)
		{
			size_t matrix_sz = device_sm[dev_id] > 500 ? sizeof(uint64_t) * 4 * 4 : sizeof(uint64_t) * 8 * 8 * 3 * 4;
			d_matrix_size = matrix_sz;
			CUDA_SAFE_CALL(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput));
			lyra2Z_cpu_init(thr_id, throughput, d_matrix[thr_id]);
		}
		else
			lyra2Z_cpu_init_sm2(thr_id, throughput);

		CUDA_SAFE_CALL(cudaMalloc(&d_hash[thr_id], d_hash_size_bytes()));

		init[thr_id] = true;
	}

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	blake256_cpu_setBlock_80(pdata);
	lyra2Z_setTarget(ptarget);

	do {
		int order = 0;

		blake256_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id], order++);

		*hashes_done = pdata[19] - first_nonce + throughput;

		work->nonces[0] = lyra2Z_cpu_hash_32(thr_id, throughput, pdata[19], d_hash[thr_id], gtx750ti);

		if (work->nonces[0] != UINT32_MAX)
		{
			uint32_t _ALIGN(64) vhash[8];

			be32enc(&endiandata[19], work->nonces[0]);
			lyra2Z_hash(vhash, endiandata);

			if (vhash[7] <= ptarget[7] && fulltest(vhash, ptarget)) {
				work->valid_nonces = 1;
				work->nonces[1] = lyra2Z_getSecNonce(thr_id, 1);
				work_set_target_ratio(work, vhash);
				pdata[19] = work->nonces[0] + 1;
				if (work->nonces[1] != UINT32_MAX)
				{
					be32enc(&endiandata[19], work->nonces[1]);
					lyra2Z_hash(vhash, endiandata);
					if (vhash[7] <= ptarget[7] && fulltest(vhash, ptarget)) {
						bn_set_target_ratio(work, vhash, 1);
						work->valid_nonces++;
					}
					pdata[19] = max(work->nonces[0], work->nonces[1]) + 1; // cursor
				}
				return work->valid_nonces;
			}
			else if (vhash[7] > ptarget[7]) {
				gpu_increment_reject(thr_id);
				maybe_report_bad_nonce(thr_id, ptarget[7], vhash[7], work->nonces[0], pdata[19]);
				pdata[19] = work->nonces[0];

				if (opt_cuda_memcheck)
					break;
				else
					continue;
			}
		}

		if ((uint64_t)throughput + pdata[19] >= max_nonce) {
			pdata[19] = max_nonce;
			break;
		}
		pdata[19] += throughput;

		if (opt_cuda_memcheck)
			break;

	} while (!work_restart[thr_id].restart);

	*hashes_done = pdata[19] - first_nonce;
	return 0;
}

extern "C" int scanhash_lyra2Zz(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[28];
	const uint32_t first_nonce = pdata[19];
	int dev_id = device_map[thr_id];

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

	gpulog(LOG_BLUE, thr_id, "Device shader model: %i", device_sm[thr_id % MAX_GPUS]);

	if (!init[thr_id])
	{
		cudaSetDevice(dev_id);
		if (opt_cudaschedule == -1 && gpu_threads == 1) {
			cudaDeviceReset();
			cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
			CUDA_LOG_ERROR();
		}

		cuda_get_arch(thr_id);
		int intensity = (device_sm[dev_id] > 500 && !is_windows()) ? 17 : 16;
		if (device_sm[dev_id] <= 500) intensity = 15;
		throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
		if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

		cudaDeviceProp props;
		cudaGetDeviceProperties(&props, dev_id);
		gtx750ti = (strstr(props.name, "750 Ti") != NULL);

		gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

		blake256_cpu_init(thr_id, throughput);

		if (device_sm[dev_id] >= 500) {
			size_t matrix_sz = device_sm[dev_id] > 500 ? sizeof(uint64_t) * 4 * 4 : sizeof(uint64_t) * 8 * 8 * 3 * 4;
			d_matrix_size = matrix_sz;
			CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput));
			lyra2Zz_cpu_init(thr_id, throughput, d_matrix[thr_id]);

		} else {

			gpulog(LOG_ERR, thr_id, "Lyra2Zz requires at least shader model 5.0 to work! This device doesn't meet the requirement. Exiting...",
				device_sm[dev_id]);

			return 0;
		}

		CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_hash[thr_id], d_hash_size_bytes()));

		init[thr_id] = true;
	}
	
	for (int k=0; k < 28; k++) {
		be32enc(&endiandata[k], pdata[k]);
	}

	blake256_cpu_setBlock_112(endiandata);
	memcpy(endiandata, pdata, sizeof(endiandata));
	
	lyra2Zz_setTarget(ptarget);

	__time64_t debug_interval_start = _time64(NULL);


	do {
		struct timeval hash_time, start_iter, end_hash;

		gettimeofday(&start_iter, NULL);

		int order = 0;

		blake256_cpu_hash_112(thr_id, throughput, pdata[19], d_hash[thr_id], order++);

		*hashes_done = pdata[19] - first_nonce + throughput;

		work->nonces[0] = lyra2Zz_cpu_hash_32(thr_id, throughput, pdata[19], d_hash[thr_id], gtx750ti);
		
		gettimeofday(&end_hash, NULL);
		timeval_subtract(&hash_time, &end_hash, &start_iter);
		
		if (work->nonces[0] != UINT32_MAX)
		{
			uint32_t _ALIGN(64) vhash[8];

			be32enc(&endiandata[19], work->nonces[0]);
			//endiandata[19] = work->nonces[0];
			lyra2Z_hash_112(vhash, endiandata);
			
			if (vhash[7] <= ptarget[7] && fulltest(vhash, ptarget)) {
				work->valid_nonces = 1;
				work->nonces[1] = lyra2Z_getSecNonce(thr_id, 1);
				work_set_target_ratio(work, vhash);
				pdata[19] = work->nonces[0] + 1;
				if (work->nonces[1] != UINT32_MAX)
				{
					be32enc(&endiandata[19], work->nonces[1]);
					lyra2Z_hash_112(vhash, endiandata);

					if (vhash[7] <= ptarget[7] && fulltest(vhash, ptarget)) {
						bn_set_target_ratio(work, vhash, 1);
						work->valid_nonces++;
					}
					pdata[19] = max(work->nonces[0], work->nonces[1]) + 1; // cursor
				}
				return work->valid_nonces;
			}
			else if (vhash[7] > ptarget[7]) {
				gpu_increment_reject(thr_id);
				maybe_report_bad_nonce(thr_id, ptarget[7], vhash[7], work->nonces[0], pdata[19]);
				pdata[19] = work->nonces[0];
				
				if (opt_cuda_memcheck)
					break;
				else
					continue;
			}
		}

		__time64_t test_time = _time64(NULL);

		if (opt_debug && opt_print_interval != OPT_PRINT_INTERVAL_UNSET) {
			if (test_time - debug_interval_start >= opt_print_interval) {
				double dtime = (double) hash_time.tv_sec + 1e-6 * (double) hash_time.tv_usec;
				applog(
					LOG_BLUE, 
					"[%i second update] Hash time (of most recent run, in seconds) %f, Nonce: 0x%x", 
					opt_print_interval, dtime, pdata[19]);
			
				debug_interval_start = test_time;
			}
		}

		if ((uint64_t) throughput + (uint64_t) pdata[19] >= (uint64_t) max_nonce) {
			pdata[19] = max_nonce;
			break;
		}
		pdata[19] += throughput;

		if (opt_cuda_memcheck)
			break;

	} while (!work_restart[thr_id].restart);

	*hashes_done = pdata[19] - first_nonce;
	return 0;
}

// cleanup
extern "C" void free_lyra2Z(int thr_id)
{
	int dev_id = device_map[thr_id];
	if (!init[thr_id])
		return;

	cudaThreadSynchronize();

	cudaFree(d_hash[thr_id]);
	if (device_sm[dev_id] >= 350)
		cudaFree(d_matrix[thr_id]);
	lyra2Z_cpu_free(thr_id);

	init[thr_id] = false;

	cudaDeviceSynchronize();
}

static bool test_hash(int thr_id, uint32_t *input28)
{
	uint32_t start_n = input28[19];

	uint32_t adata[28];

	for (uint32_t i = 0; i < 28; ++i)
		be32enc(adata + i, input28[i]);

	blake256_cpu_init(thr_id, throughput);
	blake256_cpu_setBlock_112(adata);
	blake256_cpu_hash_112(thr_id, throughput, start_n, d_hash[thr_id], 0);

	uint256 target = uint256().SetCompact(input28[18]);
	lyra2Zz_setTarget(target.begin());
	lyra2Zz_cpu_hash_32(thr_id, throughput, start_n, d_hash[thr_id], gtx750ti);

	uint32_t correct = 0;

	for (size_t thread = 0; thread < throughput; ++thread) {				
		uint64_t gpu_state_hash[4];

		uint32_t out[8];
		be32enc(&input28[19], start_n + thread);
			
		lyra2Z_hash_112(out, input28);

		cudaMemcpy(
			&gpu_state_hash[0], 
			d_matrix[thr_id] + 0 * throughput + (thread * 4), 
			sizeof(gpu_state_hash), 
			cudaMemcpyDeviceToHost
		);

		if (memcmp(gpu_state_hash, out, sizeof(gpu_state_hash)) == 0) {
			correct++;
		}
	}

	return correct == throughput;
}

static bool niche_test(int thr_id)
{
	uint32_t testinput[28] = {
		0xa1e11c82,
		0xd2e52f4e,
		0x861eaf2d,
		0xe2ff5391,
		0x6e593b13,
		0xa698dc59,
		0xc1b59839,
		0x6e82926c,
		0x83bc8fcd,
		0x317ac43d,
		0x86c256f1,
		0x8b672c1b,
		0x81b7489e,
		0xa0d2a889,
		0x98862717,
		0x3a2d2244,
		0xeb5f6d94,
		0x8f7bb10e,
		0xdc14c194,
		0x00000000,
		0xc70194c4,
		0xeeb2112c,
		0x5e577c0e,
		0x0e39f176,
		0x6deddd3d,
		0xb3e09d44,
		0x624233d4,
		0x16f910b8
	};

	testinput[19] = 0;


	return test_hash(thr_id, testinput);
}

static bool large_test(int thr_id)
{
#ifdef _MSC_VER
	uint32_t correct = 0;
	const uint32_t num_tests = 1 << 8;

	LPCSTR cryptname = __FUNCTION__;
	HCRYPTPROV hCryptProv = NULL;

	if (!CryptAcquireContext(&hCryptProv, cryptname, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		if (GetLastError() == NTE_EXISTS) {
			if (!CryptAcquireContext(&hCryptProv, cryptname, NULL, PROV_RSA_FULL, 0))
				goto ret_crypt_error;
		} else {
			goto ret_crypt_error;
		}
	}

	for (uint32_t i = 0; i < num_tests; ++i) {
		uint32_t adata[28];
		
		if (!CryptGenRandom(hCryptProv, sizeof(adata), (BYTE *)&adata[0])) {
			applog(
				LOG_WARNING, 
				__FUNCTION__ " Could not randomly generate buffer for iteration %u. Error: 0x%x\n", 
				i, 
				GetLastError()
			);
			continue;
		}

		adata[19] = 0;

		if (test_hash(thr_id, adata))
			correct++;
	}

	CryptReleaseContext(hCryptProv, NULL);
	return correct == num_tests;

ret_crypt_error:
	applog(LOG_ERR, __FUNCTION__ " Could not get windows cryptography context - error returned: 0x%x\n", GetLastError());
		return false;
#endif

	return false;
}

extern "C" int lyra2Zz_test_hash(int thr_id, uint32_t *block_data)
{
	maybe_init_thread_data(thr_id, 0, UINT32_MAX, 0);
	return large_test(thr_id);
}


