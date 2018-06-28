/**
 * Lyra2 (v1) cuda implementation based on djm34 work
 * tpruvot@github 2015, Nanashi 08/2016 (from 1.8-r2)
 * Lyra2Z implentation for Zcoin based on all the previous
 * djm34 2017
 **/

#include <stdio.h>
#include <memory.h>

#define TPB52 32
#define TPB30 160
#define TPB20 160

#include "cuda_lyra2Zz_sm5.cuh"
	
	//#include "cuda_lyra2Zz_sm5.cuh"

#ifdef __INTELLISENSE__
/* just for vstudio code colors */
__device__ uint32_t __shfl(uint32_t a, uint32_t b, uint32_t c);
#define atomicMin()
#define __CUDA_ARCH__ 500
#endif

static uint32_t *h_GNonces[16]; // this need to get fixed as the rest of that routine
static uint32_t *d_GNonces[16];

#define reduceDuplexRow(rowIn, rowInOut, rowOut) { \
	for (int i = 0; i < 8; i++) { \
		for (int j = 0; j < 12; j++) \
			state[j] ^= Matrix[12 * i + j][rowIn] + Matrix[12 * i + j][rowInOut]; \
		round_lyra_sm2(state); \
		for (int j = 0; j < 12; j++) \
			Matrix[j + 12 * i][rowOut] ^= state[j]; \
		Matrix[0 + 12 * i][rowInOut] ^= state[11]; \
		Matrix[1 + 12 * i][rowInOut] ^= state[0]; \
		Matrix[2 + 12 * i][rowInOut] ^= state[1]; \
		Matrix[3 + 12 * i][rowInOut] ^= state[2]; \
		Matrix[4 + 12 * i][rowInOut] ^= state[3]; \
		Matrix[5 + 12 * i][rowInOut] ^= state[4]; \
		Matrix[6 + 12 * i][rowInOut] ^= state[5]; \
		Matrix[7 + 12 * i][rowInOut] ^= state[6]; \
		Matrix[8 + 12 * i][rowInOut] ^= state[7]; \
		Matrix[9 + 12 * i][rowInOut] ^= state[8]; \
		Matrix[10+ 12 * i][rowInOut] ^= state[9]; \
		Matrix[11+ 12 * i][rowInOut] ^= state[10]; \
	} \
  }

#define absorbblock(in)  { \
	state[0] ^= Matrix[0][in]; \
	state[1] ^= Matrix[1][in]; \
	state[2] ^= Matrix[2][in]; \
	state[3] ^= Matrix[3][in]; \
	state[4] ^= Matrix[4][in]; \
	state[5] ^= Matrix[5][in]; \
	state[6] ^= Matrix[6][in]; \
	state[7] ^= Matrix[7][in]; \
	state[8] ^= Matrix[8][in]; \
	state[9] ^= Matrix[9][in]; \
	state[10] ^= Matrix[10][in]; \
	state[11] ^= Matrix[11][in]; \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
	round_lyra_sm2(state); \
  }

__device__ __forceinline__
static void round_lyra_sm2(uint2 *s)
{
	l2ZZ::Gfunc(s[0], s[4], s[8], s[12]);
	l2ZZ::Gfunc(s[1], s[5], s[9], s[13]);
	l2ZZ::Gfunc(s[2], s[6], s[10], s[14]);
	l2ZZ::Gfunc(s[3], s[7], s[11], s[15]);
	l2ZZ::Gfunc(s[0], s[5], s[10], s[15]);
	l2ZZ::Gfunc(s[1], s[6], s[11], s[12]);
	l2ZZ::Gfunc(s[2], s[7], s[8], s[13]);
	l2ZZ::Gfunc(s[3], s[4], s[9], s[14]);
}

__device__ __forceinline__
void reduceDuplexRowSetup(const int rowIn, const int rowInOut, const int rowOut, uint2 state[16], uint2 Matrix[96][8])
{
#if __CUDA_ARCH__ > 500
#pragma unroll
#endif
	for (int i = 0; i < 8; i++)
	{
		#pragma unroll
		for (int j = 0; j < 12; j++)
			state[j] ^= Matrix[12 * i + j][rowIn] + Matrix[12 * i + j][rowInOut];

		round_lyra_sm2(state);

		#pragma unroll
		for (int j = 0; j < 12; j++)
			Matrix[j + 84 - 12 * i][rowOut] = Matrix[12 * i + j][rowIn] ^ state[j];

		Matrix[0 +  12 * i][rowInOut] ^= state[11];
		Matrix[1 +  12 * i][rowInOut] ^= state[0];
		Matrix[2 +  12 * i][rowInOut] ^= state[1];
		Matrix[3 +  12 * i][rowInOut] ^= state[2];
		Matrix[4 +  12 * i][rowInOut] ^= state[3];
		Matrix[5 +  12 * i][rowInOut] ^= state[4];
		Matrix[6 +  12 * i][rowInOut] ^= state[5];
		Matrix[7 +  12 * i][rowInOut] ^= state[6];
		Matrix[8 +  12 * i][rowInOut] ^= state[7];
		Matrix[9 +  12 * i][rowInOut] ^= state[8];
		Matrix[10 + 12 * i][rowInOut] ^= state[9];
		Matrix[11 + 12 * i][rowInOut] ^= state[10];
	}
}

#if __CUDA_ARCH__ < 350


// TODO

#endif

__host__
void lyra2Zz_cpu_init(int thr_id, uint32_t threads, uint64_t *d_matrix)
{
	// just assign the device pointer allocated in main loop
	CUDA_SAFE_CALL_PAUSE(cudaMemcpyToSymbol(l2ZZ::DMatrix, &d_matrix, sizeof(uint64_t*), 0, cudaMemcpyHostToDevice));
	CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_GNonces[thr_id], 2 * sizeof(uint32_t)));
	CUDA_SAFE_CALL_PAUSE(cudaMallocHost(&h_GNonces[thr_id], 2 * sizeof(uint32_t)));
}

__host__
void lyra2Zz_cpu_init_sm2(int thr_id, uint32_t threads)
{
	// just assign the device pointer allocated in main loop
	CUDA_SAFE_CALL_PAUSE(cudaMalloc(&d_GNonces[thr_id], 2 * sizeof(uint32_t)));
	CUDA_SAFE_CALL_PAUSE(cudaMallocHost(&h_GNonces[thr_id], 2 * sizeof(uint32_t)));
}

__host__
void lyra2Zz_cpu_free(int thr_id)
{
	CUDA_SAFE_CALL_PAUSE(cudaFree(d_GNonces[thr_id]));
	CUDA_SAFE_CALL_PAUSE(cudaFreeHost(h_GNonces[thr_id]));
}

__host__
uint32_t lyra2Zz_getSecNonce(int thr_id, int num)
{
	uint32_t results[2];
	memset(results, 0xFF, sizeof(results));
	CUDA_SAFE_CALL_PAUSE(cudaMemcpy(results, d_GNonces[thr_id], sizeof(results), cudaMemcpyDeviceToHost));
	if (results[1] == results[0])
		return UINT32_MAX;
	return results[num];
}

__host__
void lyra2Zz_setTarget(const void *pTargetIn)
{
	CUDA_SAFE_CALL_PAUSE(cudaMemcpyToSymbol(l2ZZ::pTarget, pTargetIn, 32, 0, cudaMemcpyHostToDevice));
}

__host__
uint32_t lyra2Zz_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce, uint64_t *d_hash0, bool gtx750ti)
{
	uint32_t result = UINT32_MAX;
	CUDA_SAFE_CALL_PAUSE(cudaMemset(d_GNonces[thr_id], 0xff, 2 * sizeof(uint32_t)));
	int dev_id = device_map[thr_id % MAX_GPUS];

	uint32_t tpb = TPB52;

	if (device_sm[dev_id] == 500)
		tpb = TPB50;
	if (device_sm[dev_id] == 200)
		tpb = TPB20;

	dim3 grid1((threads * 4 + tpb - 1) / tpb);
	dim3 block1(4, tpb >> 2);

	dim3 grid2((threads + 64 - 1) / 64);
	dim3 block2(64);

	dim3 grid3((threads + tpb - 1) / tpb);
	dim3 block3(tpb);
	
	{
		size_t shared_mem = 0;

		if (gtx750ti)
			// suitable amount to adjust for 8warp
			shared_mem = 8192;
		else
			// suitable amount to adjust for 10warp
			shared_mem = 6144;

		l2ZZ::lyra2Zz_gpu_hash_32_1_sm5 <<< grid2, block2 >>> (threads, startNounce, (uint2*)d_hash0);

		l2ZZ::lyra2Zz_gpu_hash_32_2_sm5 <<< grid1, block1, shared_mem >>> (threads, startNounce, (uint2*)d_hash0);

		l2ZZ::lyra2Zz_gpu_hash_32_3_sm5 <<< grid2, block2 >>> (threads, startNounce, (uint2*)d_hash0, d_GNonces[thr_id]);
	}

	// get first found nonce
	CUDA_SAFE_CALL_PAUSE(cudaMemcpy(h_GNonces[thr_id], d_GNonces[thr_id], 1 * sizeof(uint32_t), cudaMemcpyDeviceToHost));
	result = *h_GNonces[thr_id];

	return result;
}
