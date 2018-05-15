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
		lyra2Z_cpu_init(thr_id, throughput, d_matrix[thr_id]);
	}
	else
		lyra2Z_cpu_init_sm2(thr_id, throughput);

	CUDA_SAFE_CALL(cudaMalloc(&d_hash[thr_id], d_hash_size_bytes()));

	init[thr_id] = true;
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
				if (!opt_quiet)	gpulog(LOG_WARNING, thr_id,
					"result for %08x does not validate on CPU!", work->nonces[0]);
				pdata[19] = work->nonces[0];
				continue;
			}
		}

		if ((uint64_t)throughput + pdata[19] >= max_nonce) {
			pdata[19] = max_nonce;
			break;
		}
		pdata[19] += throughput;

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

	for (int k=0; k < 28; k++)
		be32enc(&endiandata[k], pdata[k]);

	blake256_cpu_setBlock_112(pdata);
	lyra2Z_setTarget(ptarget);

	do {
		int order = 0;

		blake256_cpu_hash_112(thr_id, throughput, pdata[19], d_hash[thr_id], order++);

		*hashes_done = pdata[19] - first_nonce + throughput;

		work->nonces[0] = lyra2Z_cpu_hash_32(thr_id, throughput, pdata[19], d_hash[thr_id], gtx750ti);

		if (work->nonces[0] != UINT32_MAX)
		{
			uint32_t _ALIGN(64) vhash[8];

			be32enc(&endiandata[19], work->nonces[0]);

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
				if (!opt_quiet)	gpulog(LOG_WARNING, thr_id,
					"result for %08x does not validate on CPU!", work->nonces[0]);
				pdata[19] = work->nonces[0];
				continue;
			}
		}

		if ((uint64_t)throughput + pdata[19] >= max_nonce) {
			pdata[19] = max_nonce;
			break;
		}
		pdata[19] += throughput;

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

/* UNIT TESTING */

#define COPY_D_PRETEST		\
	if (!dest)				\
		return false;		\
	if (!len)				\
		return false;		\
	if (!init[thr_id])		\
		return false

#define COPY_D_ALLOC_DEST(sz)			\
	*dest = (uint64_t *) malloc(sz);	\
	if (!(*dest))						\
		return false;					\
	memset(*dest, 0, sz)

static int lyra2Z_copy_d_hash(int thr_id, uint64_t **dest, size_t *len)
{
	COPY_D_PRETEST;

	size_t sz = d_hash_size_bytes();
	*len = sz >> 3;
	
	COPY_D_ALLOC_DEST(sz);
	CUDA_SAFE_CALL(cudaMemcpy(*dest, d_hash[thr_id], sz, cudaMemcpyDeviceToHost));

	return true;
}

static int lyra2Z_copy_d_matrix(int thr_id, uint64_t **dest, size_t *len)
{
 	COPY_D_PRETEST;

	size_t sz = throughput * d_matrix_size;
	*len = sz >> 3;

	COPY_D_ALLOC_DEST(sz);
	CUDA_SAFE_CALL(cudaMemcpy(*dest, d_matrix[thr_id], sz, cudaMemcpyDeviceToHost));
	return true;
}


/*	note that the pure CPU variant of Lyra2Z will 
	automatically blake256 the input before running
	its algorithm; the GPU version naturally just
	grabs the data from where the most recent GPU blake256
	results were written */

static void lyra2Z_blake_80_pre_test(int thr_id, uint32_t *block_data, uint32_t *endiandata)
{
	blake256_cpu_setBlock_80(block_data);
	blake256_cpu_hash_80(thr_id, throughput, block_data[19], d_hash[thr_id], 0);
}

static void lyra2Z_blake_80_cpu_hash_test(uint8_t *out_hash_cpu, uint32_t *thread_block_data_cpu)
{
	blake256hash(out_hash_cpu, thread_block_data_cpu, 14);
}

static bool lyr2aZ_blake_80_read_gpu_hash(size_t thread, size_t gpulen64, uint64_t *hash_gpu, uint64_t *hash)
{
	for (size_t i = 0; i < 4; ++i) {
		size_t index = i * throughput + thread;

		if (index >= gpulen64) {
			return false;
		}

		memcpy(hash + i, hash_gpu + index, sizeof(hash[0]));
	}

	return true;
}

static void lyra2Z_lyra_80_cpu_hash_test(uint8_t *out_hash_cpu, uint32_t *thread_block_data_cpu)
{
	lyra2Z_hash(out_hash_cpu, thread_block_data_cpu);
}

static void lyra2Z_lyra_80_pre_test(int thr_id, uint32_t *block_data, uint32_t *endiandata)
{
	uint256 target = uint256().SetCompact(block_data[18]);
	lyra2Z_setTarget(target.begin());
	lyra2Z_cpu_hash_32(thr_id, throughput, block_data[19], d_hash[thr_id], gtx750ti);
}

static bool lyra2Z_lyra_80_read_gpu_hash(size_t thread, size_t gpulen64, uint64_t *hash_gpu, uint64_t *hash)
{
	memcpy(hash, hash_gpu + (0 * throughput + thread) * 4, 32);

	return true;
}

typedef void (*cpu_hash_test_fn_t)(uint8_t *out_hash_cpu, uint32_t *thread_block_data_cpu);
typedef void (*gpu_pre_test_fn_t)(int thr_id, uint32_t *block_data, uint32_t *endiandata);
typedef int (*copy_gpu_data_fn_t)(int thr_id, uint64_t **dest, size_t *gpulen);
typedef bool (*read_gpu_hash_fn_t)(size_t thread, size_t gpulen64, uint64_t *hash_gpu, uint64_t *hash);

static const char *test_names[] = {
	"lyra2Z_blake_80_test",
	"lyra2Z_lyra_80_test"
};

template <
	int test_name_index,
	cpu_hash_test_fn_t cpu_hash_test_fn, 
	gpu_pre_test_fn_t gpu_pretest_fn,
	copy_gpu_data_fn_t get_gpu_data,
	read_gpu_hash_fn_t read_gpu_hash
>
static bool lyra2Z_hash_test(int thr_id, uint32_t *block_data, uint32_t *endiandata)
{
	static const char* err[3] = {
		"gpu thread index out of bounds",
		"hash difference found",
		"could not copy gpu hash memory to host"
	};

	const volatile int name_index = test_name_index; (void) name_index; // debug 

	int err_index = -1;

	gpu_pretest_fn(thr_id, block_data, endiandata);

	uint64_t *hash_gpu = nullptr;
	
	size_t gpulen64 = 0;

	if (!get_gpu_data(thr_id, &hash_gpu, &gpulen64)) {
		err_index = 2;
		goto fail;
	}

	for (size_t thread = 0; thread < throughput; ++thread) {
		uint32_t thread_block_data_cpu[20];

		for (size_t i = 0; i < 20; ++i)
			be32enc(&thread_block_data_cpu[i], block_data[i]);

		be32enc(&thread_block_data_cpu[19], block_data[19] + thread);

		uint8_t hash_cpu[32];

		cpu_hash_test_fn(hash_cpu, thread_block_data_cpu);

		uint64_t hash[4];
		if (!read_gpu_hash(thread, gpulen64, hash_gpu, hash)) {
			err_index = 0;
			goto fail;
		}
		
		if (memcmp(hash_cpu, hash, sizeof(hash)) != 0) {
			err_index = 1;
			goto fail;
		}
	}
		
	applog(LOG_INFO, "[%s] GPU/CPU hash test succeeded", test_names[test_name_index]);
	free(hash_gpu);
	return true;

fail:
	applog(LOG_ERR, "[%s] hash failure %s", err[err_index], test_names[test_name_index]);
	if (hash_gpu)
		free(hash_gpu);
	return false;
}

static bool lyra2Z_blake_test_80(int thr_id, uint32_t *block_data, uint32_t *endiandata)
{
	return lyra2Z_hash_test<
		0, 
		lyra2Z_blake_80_cpu_hash_test, 
		lyra2Z_blake_80_pre_test,
		lyra2Z_copy_d_hash,
		lyr2aZ_blake_80_read_gpu_hash
	>(
		thr_id, block_data, endiandata);
}

static bool lyra2Z_lyra_test_80(int thr_id, uint32_t *block_data, uint32_t *endiandata)
{
	return lyra2Z_hash_test<
		1, 
		lyra2Z_lyra_80_cpu_hash_test, 
		lyra2Z_lyra_80_pre_test,
		lyra2Z_copy_d_matrix,
		lyra2Z_lyra_80_read_gpu_hash
	>(
		thr_id, block_data, endiandata);
}

extern "C" int lyra2Z_test_blake_80(int thr_id, uint32_t *block_data)
{
	block_data[19] = 0;

	maybe_init_thread_data(thr_id, 0, UINT32_MAX, block_data[19]);

	uint32_t endiandata[20];

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], block_data[k]);
	
	if (!lyra2Z_blake_test_80(thr_id, block_data, endiandata))
		return false;

	if (!lyra2Z_lyra_test_80(thr_id, block_data, endiandata))
		return false;

	return true;
}


