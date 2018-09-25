#include "uint256.h"

extern "C" {
#include <sph/sph_blake.h>
#include "Lyra2Z.h"
}

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

// cleanup
extern "C" void free_lyra2Z(int thr_id)
{
	int dev_id = device_map[thr_id];
	if (!init[thr_id])
		return;

	CUDA_SAFE_CALL_PAUSE(cudaThreadSynchronize());

	CUDA_SAFE_CALL_PAUSE(cudaFree(d_hash[thr_id]));
	if (device_sm[dev_id] >= 350) {
		CUDA_SAFE_CALL_PAUSE(cudaFree(d_matrix[thr_id]));
	}

	lyra2Z_cpu_free(thr_id);

	init[thr_id] = false;

	CUDA_SAFE_CALL_PAUSE(cudaDeviceSynchronize());
}




