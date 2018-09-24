#include "uint256.h"

extern "C" {
#include <sph/sph_blake.h>
#include "Lyra2Z.h"
}

#include "Lyra2Zz.h"

#include <miner.h>
#include <cuda_helper.h>
#include <memory>

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

extern bool get_work(struct thr_info *thr, struct work *work);

extern int algo_mutex_try_lock(void);
extern void algo_mutex_try_unlock(void);

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

static int maybe_init_thread_data(int thr_id, int dev_id, uint32_t max_nonce, uint32_t first_nonce, bool l2zz)
{
	if (init[thr_id])
		return true;

	CUDA_SAFE_CALL_PAUSE(cudaSetDevice(dev_id));

	if (opt_cudaschedule == -1 && gpu_threads == 1) {
		CUDA_SAFE_CALL_PAUSE(cudaDeviceReset());
		CUDA_SAFE_CALL_PAUSE(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));
		CUDA_LOG_ERROR();
	}

	cuda_get_arch(thr_id);
	int intensity = (device_sm[dev_id] > 500 && !is_windows()) ? 17 : 16;
	if (device_sm[dev_id] <= 500) intensity = 15;
	throughput = cuda_default_throughput(thr_id, 1U << intensity); // 18=256*256*4;
	if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

	cudaDeviceProp props;
	CUDA_SAFE_CALL_PAUSE(cudaGetDeviceProperties(&props, dev_id));
	gtx750ti = (strstr(props.name, "750 Ti") != NULL);

	gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

	blake256_cpu_init(thr_id, throughput);

	size_t matrix_sz = device_sm[dev_id] > 500 ? sizeof(uint64_t) * 4 * 4 : sizeof(uint64_t) * 8 * 8 * 3 * 4;
	d_matrix_size = matrix_sz;

	if (l2zz) {
		if (device_sm[dev_id] >= 500) {
			CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput));
			lyra2Zz_cpu_init(thr_id, throughput, d_matrix[thr_id]);
		} else {
			gpulog(LOG_ERR, thr_id, "Lyra2Zz requires at least shader model 5.0 to work! This device doesn't meet the requirement. Exiting...",
				device_sm[dev_id]);

			return false;
		}
	} else {
		CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput));

		if (device_sm[dev_id] >= 350) {				
			lyra2Z_cpu_init(thr_id, throughput, d_matrix[thr_id]);
		} else {
			lyra2Z_cpu_init_sm2(thr_id, throughput);
		}
	}

	CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_hash[thr_id], d_hash_size_bytes()));

	init[thr_id] = true;	
	return true;
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

static inline void log_shadermodel(int thr_id)
{
	gpulog(LOG_BLUE, thr_id, "Device shader model: %i", device_sm[thr_id % MAX_GPUS]);
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
		CUDA_SAFE_CALL(cudaSetDevice(dev_id));
		if (opt_cudaschedule == -1 && gpu_threads == 1) {
			CUDA_SAFE_CALL(cudaDeviceReset());
			CUDA_SAFE_CALL(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));
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

class l2zz_update_timer {
public:
	struct timeval interval_start;
	long interval_amt_usec;

	l2zz_update_timer(long amt_msec)
		:	interval_amt_usec(amt_msec * 1000)
	{
		gettimeofday(&interval_start, nullptr);
	}

	long to_usec(struct timeval *in) const
	{
		return in->tv_sec * 1000000 + in->tv_usec;
	}

	bool query()
	{
		struct timeval test;
		gettimeofday(&test, nullptr);

		struct timeval diff_res;
		bool neg = timeval_subtract(&diff_res, &test, &interval_start);
		long diff_usec = to_usec(&diff_res);
		bool r = diff_usec >= interval_amt_usec && !neg; 

		interval_start.tv_sec = r ? test.tv_sec : interval_start.tv_sec;
		interval_start.tv_usec = r ? test.tv_usec : interval_start.tv_usec;

		return r;
	}
};

#define L2ZZ_LOGSTR_SIZE (sizeof(char) * ((LYRA2ZZ_BLOCK_HEADER_LEN_BYTES << 1) + 1))

class l2zz_staleblock_query 
{
public:
	struct work * work_cmp[MAX_GPUS];
	char * str_work_data[MAX_GPUS];
	char * str_work_data_cmp[MAX_GPUS];
	l2zz_update_timer * timers[MAX_GPUS];

	l2zz_staleblock_query(void)
	{
		memset(work_cmp, 0, sizeof(work_cmp));
		memset(str_work_data, 0, sizeof(str_work_data));
		memset(str_work_data_cmp, 0, sizeof(str_work_data_cmp));
		memset(timers, 0, sizeof(timers));
	}

	~l2zz_staleblock_query(void)
	{
		for (int i = 0; i < opt_n_threads; ++i)
			if (i < MAX_GPUS)
				destroy(i);
	}

	bool valid(int thr_id) const
	{
		return str_work_data[thr_id] && str_work_data_cmp[thr_id] && work_cmp[thr_id] && timers[thr_id];
	}

	bool init(int thr_id)
	{
		bool log = !valid(thr_id) && !opt_quiet && opt_debug;

		if (!timers[thr_id]) {
			timers[thr_id] = new l2zz_update_timer(30000);
		}

		maybe_try_aligned_calloc_or_retfalse(work_cmp[thr_id], struct work, sizeof (struct work));
		maybe_try_bzalloc_or_retfalse(str_work_data[thr_id], char, L2ZZ_LOGSTR_SIZE);
		maybe_try_bzalloc_or_retfalse(str_work_data_cmp[thr_id], char, L2ZZ_LOGSTR_SIZE);

		if (log) {
			applog(LOG_DEBUG, LYRA2ZZ_LOG_HEADER "[%i] memory allocated", thr_id);
		}

		return true;
	}

	void destroy(int thr_id)
	{
		safe_aligned_free(work_cmp[thr_id]);
		safe_free(str_work_data[thr_id]);
		safe_free(str_work_data_cmp[thr_id]);

		if (timers[thr_id]) {
			delete timers[thr_id];
			timers[thr_id] = nullptr;
		}

		applog(LOG_INFO, LYRA2ZZ_LOG_HEADER "[%i] freed memory", thr_id);
	}

	bool stale_block_check(int thr_id, struct work * curr_work)
	{
		if (!valid(thr_id))
			return false;

		struct work * wcmp = work_cmp[thr_id];

		if (timers[thr_id]->query()) {
			bool did_succeed = get_work(&thr_info[thr_id], wcmp);
			bool cmp_diff = did_succeed && memcmp(curr_work->data + 1, wcmp->data + 1, 32) != 0;

			bool txupdate = false;

			if (!cmp_diff) {
				cmp_diff = did_succeed && memcmp(curr_work->lyratxs, wcmp->lyratxs, sizeof(curr_work->lyratxs)) != 0;
				txupdate = cmp_diff;
			}

			if (!opt_quiet) {
				if (cmp_diff) {
					if (txupdate) {
						applog(LOG_INFO, LYRA2ZZ_LOG_HEADER "[%i] New transaction information received. Restarting...", thr_id);
					} else {
						char * swd = str_work_data[thr_id];
						char * swcd = str_work_data_cmp[thr_id];

						memset(swd, 0, L2ZZ_LOGSTR_SIZE);
						memset(swcd, 0, L2ZZ_LOGSTR_SIZE);

						cbin2hex(swd, (const char *)(&curr_work->data[1]), 32);
						chexrev(swd);

						cbin2hex(swcd, (const char *)(&wcmp->data[1]), 32);
						chexrev(swcd);

						applog(
							LOG_INFO,
							LYRA2ZZ_LOG_HEADER "\n\n[%i] New Header\n"
							"\tReplacing: %s\n"
							"\tWith: %s\n", 
							thr_id, swd, swcd
						);
					}
				} else if (did_succeed) {
					applog(
						LOG_INFO,
						LYRA2ZZ_LOG_HEADER  
						"[%i] No change detected yet...", thr_id
					);
				} else {
					applog(LOG_ERR, LYRA2ZZ_LOG_HEADER "[%i] get_work failed...", thr_id);
				}
			}

			return cmp_diff;
		}

		return false;
	}
};

static std::unique_ptr<l2zz_staleblock_query> g_staleblock_query(nullptr);

extern "C" int scanhash_lyra2Zz(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[28];
	const uint32_t first_nonce = pdata[19];
	int dev_id = device_map[thr_id];

	int algomuterr = algo_mutex_try_lock();

	if (algomuterr == 0) {
		applog(LOG_INFO, LYRA2ZZ_LOG_HEADER "[%i] Got staleblock lock!", thr_id);

		if (!g_staleblock_query.get()) {
			g_staleblock_query.reset(new l2zz_staleblock_query());
		}

		algo_mutex_try_unlock();
	} else {
		applog(LOG_WARNING, LYRA2ZZ_LOG_HEADER "[%i] Could not get staleblock lock! Error: %i", 
			   thr_id, algomuterr);
	}

	if (opt_benchmark)
		ptarget[7] = 0x00ff;

	log_shadermodel(thr_id);

	if (!maybe_init_thread_data(thr_id, dev_id, max_nonce, first_nonce, true))
		return 0;
	
	for (int k=0; k < 28; k++) {
		be32enc(&endiandata[k], pdata[k]);
	}

	blake256_cpu_setBlock_112(endiandata);
	memcpy(endiandata, pdata, sizeof(endiandata));
	
	lyra2Zz_setTarget(ptarget);

	__time64_t debug_interval_start = 0; 

	const bool time_hash_iter = opt_debug && opt_print_interval != OPT_PRINT_INTERVAL_UNSET;

	if (time_hash_iter)
		debug_interval_start = _time64(NULL);

	if (thr_id == 0) {
		if (g_staleblock_query.get() && !g_staleblock_query->init(thr_id)) {
			applog(LOG_WARNING, LYRA2ZZ_LOG_HEADER "[%i] could not allocate stale block check memory!", thr_id);
		}
	}

	do {
		if (thr_id == 0) {
			if (g_staleblock_query.get() && g_staleblock_query->stale_block_check(thr_id, work)) {
				restart_threads();
				break;
			}
		}

		struct timeval hash_time, start_iter, end_hash;

		if (time_hash_iter)
			gettimeofday(&start_iter, NULL);

		int order = 0;

		blake256_cpu_hash_112(thr_id, throughput, pdata[19], d_hash[thr_id], order++);

		*hashes_done = pdata[19] - first_nonce + throughput;

		work->nonces[0] = lyra2Zz_cpu_hash_32(thr_id, throughput, pdata[19], d_hash[thr_id], gtx750ti);
		
		if (time_hash_iter) {
			gettimeofday(&end_hash, NULL);
			timeval_subtract(&hash_time, &end_hash, &start_iter);
		}
		
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

		if (time_hash_iter) {
			__time64_t test_time = _time64(NULL);
			
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
	size_t start_n = ((size_t)input28[19]) & 0xFFFFFFFF;

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
	int correct = 0;
	const int num_tests = 1 << 8;

	LPCSTR cryptname = __FUNCTION__;
	HCRYPTPROV hCryptProv = NULL;

	if (!CryptAcquireContext(&hCryptProv, cryptname, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		if (GetLastError() == (DWORD)NTE_EXISTS) {
			if (!CryptAcquireContext(&hCryptProv, cryptname, NULL, PROV_RSA_FULL, 0))
				goto ret_crypt_error;
		} else {
			goto ret_crypt_error;
		}
	}

	for (int i = 0; i < num_tests; ++i) {
		uint32_t adata[28];
		
		if (!CryptGenRandom(hCryptProv, sizeof(adata), (BYTE *)&adata[0])) {
			applog(
				LOG_WARNING, 
				__FUNCTION__ " Could not randomly generate buffer for iteration %i. Error: 0x%x\n", 
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

	if (opt_debug)
		applog(LOG_DEBUG, LYRA2ZZ_LOG_HEADER "[%i] correct/num_tests = %i/%i", thr_id, correct, num_tests);

	return correct == num_tests;

ret_crypt_error:
	applog(LOG_ERR, __FUNCTION__ " Could not get windows cryptography context - error returned: 0x%x\n", GetLastError());
		return false;
#else
	return false;
#endif
}

extern "C" int lyra2Zz_test_hash(int thr_id)
{
	if (thr_id == 0) {
		if (!maybe_init_thread_data(thr_id, 0, UINT32_MAX, 0, true))
			return false;

		return large_test(thr_id);
	} else {
		return true;
	}
}


