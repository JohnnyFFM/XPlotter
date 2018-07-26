#include "Nonce.h"
#include "shabal.h"
#include "mshabal.h"
#include "mshabal256.h"



namespace AVX1
{
	void work_i(const size_t local_num, unsigned long long loc_addr, unsigned long long local_startnonce, const unsigned long long local_nonces)
	{
		unsigned long long nonce;
		unsigned long long nonce1;
		unsigned long long nonce2;
		unsigned long long nonce3;
		unsigned long long nonce4;

		char *final = new char[32];
		char *gendata = new char[PLOT_SIZE +16];
		char *final1 = new char[32];
		char *final2 = new char[32];
		char *final3 = new char[32];
		char *final4 = new char[32];
		char *gendata1 = new char[PLOT_SIZE + 16];
		char *gendata2 = new char[PLOT_SIZE + 16];
		char *gendata3 = new char[PLOT_SIZE + 16];
		char *gendata4 = new char[PLOT_SIZE + 16];
		
		size_t len;
		shabal_context *x = new shabal_context[sizeof(shabal_context)];
		mshabal_context *mx = new mshabal_context[sizeof(mshabal_context)];

		int8_t *xv = reinterpret_cast<int8_t*>(&loc_addr); // optimization: reduced 8*4*nonces assignments
		for (size_t i = 0; i < 8; i++)
		{
			gendata[PLOT_SIZE + i] = xv[7 - i];
			gendata1[PLOT_SIZE + i] = xv[7 - i];
			gendata2[PLOT_SIZE + i] = xv[7 - i];
			gendata3[PLOT_SIZE + i] = xv[7 - i];
			gendata4[PLOT_SIZE + i] = xv[7 - i];
		}
		char *xv1, *xv2, *xv3, *xv4;
		
		shabal_context *init_x = new shabal_context[sizeof(shabal_context)];
		shabal_init(init_x, 256);
		mshabal_context *init_mx = new mshabal_context[sizeof(mshabal_context)];
		avx1_mshabal_init(init_mx, 256);

		for (unsigned long long n = 0; n < local_nonces;)
		{
			if (n + 4 <= local_nonces)
			{
				nonce1 = local_startnonce + n + 0;
				nonce2 = local_startnonce + n + 1;
				nonce3 = local_startnonce + n + 2;
				nonce4 = local_startnonce + n + 3;

				xv1 = reinterpret_cast<char*>(&nonce1);
				xv2 = reinterpret_cast<char*>(&nonce2);
				xv3 = reinterpret_cast<char*>(&nonce3);
				xv4 = reinterpret_cast<char*>(&nonce4);
				for (size_t i = 8; i < 16; i++)
				{
					gendata1[PLOT_SIZE + i] = xv1[15 - i];
					gendata2[PLOT_SIZE + i] = xv2[15 - i];
					gendata3[PLOT_SIZE + i] = xv3[15 - i];
					gendata4[PLOT_SIZE + i] = xv4[15 - i];
				}
				
				for (size_t i = PLOT_SIZE; i > 0; i -= HASH_SIZE)
				{
					memcpy(mx, init_mx, sizeof(*init_mx)); // optimization: avx1_mshabal_init(mx, 256);
					if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
					else len = PLOT_SIZE + 16 - i;
					avx1_mshabal(mx, &gendata1[i], &gendata2[i], &gendata3[i], &gendata4[i], len);
					avx1_mshabal_close(mx, 0, 0, 0, 0, 0, &gendata1[i - HASH_SIZE], &gendata2[i - HASH_SIZE], &gendata3[i - HASH_SIZE], &gendata4[i - HASH_SIZE]);
				}

				memcpy(mx, init_mx, sizeof(*init_mx)); // optimization: avx1_mshabal_init(mx, 256);
				avx1_mshabal(mx, gendata1, gendata2, gendata3, gendata4, PLOT_SIZE + 16);
				avx1_mshabal_close(mx, 0, 0, 0, 0, 0, final1, final2, final3, final4);

				// XOR with final
				for (size_t i = 0; i < PLOT_SIZE; i++)
				{
					gendata1[i] ^= (final1[i % 32]);
					gendata2[i] ^= (final2[i % 32]);
					gendata3[i] ^= (final3[i % 32]);
					gendata4[i] ^= (final4[i % 32]);
				}

				// Sort them:
				for (size_t i = 0; i < HASH_CAP; i ++)
				{
					memmove(&cache[i][(n + 0 + local_num*local_nonces) * SCOOP_SIZE], &gendata1[i * SCOOP_SIZE], SCOOP_SIZE);
					memmove(&cache[i][(n + 1 + local_num*local_nonces) * SCOOP_SIZE], &gendata2[i * SCOOP_SIZE], SCOOP_SIZE);
					memmove(&cache[i][(n + 2 + local_num*local_nonces) * SCOOP_SIZE], &gendata3[i * SCOOP_SIZE], SCOOP_SIZE);
					memmove(&cache[i][(n + 3 + local_num*local_nonces) * SCOOP_SIZE], &gendata4[i * SCOOP_SIZE], SCOOP_SIZE);
				}
				n += 4;
			}
			else 
			{
				_mm256_zeroupper();
				nonce = local_startnonce + n;
				xv = reinterpret_cast<int8_t*>(&nonce);

				for (size_t i = 8; i < 16; i++)	gendata[PLOT_SIZE + i] = xv[15 - i];
				
				for (size_t i = PLOT_SIZE; i > 0; i -= HASH_SIZE)
				{
					memcpy(x, init_x, sizeof(*init_x)); // optimization: shabal_init(x, 256);
					if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
					else len = PLOT_SIZE + 16 - i;

					shabal(x, &gendata[i], len);
					shabal_close(x, 0, 0, &gendata[i - HASH_SIZE]);
				}

				memcpy(x, init_x, sizeof(*init_x)); // optimization: shabal_init(x, 256);
				shabal(x, gendata, 16 + PLOT_SIZE);
				shabal_close(x, 0, 0, final);

				// XOR with final
				for (size_t i = 0; i < PLOT_SIZE; i++)			gendata[i] ^= (final[i % HASH_SIZE]);

				// Sort them:
				for (size_t i = 0; i < HASH_CAP; i++)		memmove(&cache[i][(n + local_num*local_nonces) * SCOOP_SIZE], &gendata[i * SCOOP_SIZE], SCOOP_SIZE); 
				n++;
			}
			worker_status[local_num] = n;
		}
		delete[] final;
		delete[] gendata;
		delete[] gendata1;
		delete[] gendata2;
		delete[] gendata3;
		delete[] gendata4;
		delete[] final1;
		delete[] final2;
		delete[] final3;
		delete[] final4;
		delete[] x;
		delete[] mx;
		delete[] init_mx;
		delete[] init_x;

		return;
	}
}

////////////////////////////////////////////////////////
namespace AVX2
{
	void work_i(const size_t local_num, unsigned long long loc_addr, const unsigned long long local_startnonce, const unsigned long long local_nonces)
	{
		unsigned long long nonce;
		unsigned long long nonce1;
		unsigned long long nonce2;
		unsigned long long nonce3;
		unsigned long long nonce4;
		unsigned long long nonce5;
		unsigned long long nonce6;
		unsigned long long nonce7;
		unsigned long long nonce8;

		char *final = new char[32];
		char *gendata = new char[16 + PLOT_SIZE];
		char *final1 = new char[32];
		char *final2 = new char[32];
		char *final3 = new char[32];
		char *final4 = new char[32];
		char *final5 = new char[32];
		char *final6 = new char[32];
		char *final7 = new char[32];
		char *final8 = new char[32];

		//no buffer
		//char *gendata1 = new char[16 + PLOT_SIZE];
		//char *gendata2 = new char[16 + PLOT_SIZE];
		//char *gendata3 = new char[16 + PLOT_SIZE];
		//char *gendata4 = new char[16 + PLOT_SIZE];
		//char *gendata5 = new char[16 + PLOT_SIZE];
		//char *gendata6 = new char[16 + PLOT_SIZE];
		//char *gendata7 = new char[16 + PLOT_SIZE];
		//char *gendata8 = new char[16 + PLOT_SIZE];

		size_t len;
		shabal_context *x = new shabal_context[sizeof(shabal_context)];
		mshabal256_context *mx = new mshabal256_context[sizeof(mshabal256_context)];
		
		char seed[32]; // 64bit account ID, 64bit nonce (blank), 1bit termination, 127 bits zero
		char term[32]; // 1bit 1, 255bit of zeros
		char zero[32]; // 256bit of zeros
		
		//create seed
		memmove(&seed[0], &loc_addr, 8);
		memset(&seed[8], 0, 8);
		seed[16] = -128;
		memset(&seed[17], 0, 15);
		//create zero
		memset(&zero[0], 0, 32);
		//create term
		term[0] = -128;
		memset(&term[1], 0, 31);

		// prepare smart SIMD aligned termination strings 
		// creation could further be optimized, but not much in it as it only runs once per work package
		// creation could also be moved to plotter start
		union {
			mshabal_u32 words[64 * MSHABAL256_FACTOR];
			__m256i data[16];
		} t1, t2, t3;

			for (int j = 0; j < 64 * MSHABAL256_FACTOR / 2; j += 4 * MSHABAL256_FACTOR) {
			size_t o = j / MSHABAL256_FACTOR;
			// t1
			t1.words[j + 0] = *(mshabal_u32 *)(seed + o); 
			t1.words[j + 1] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 2] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 3] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 4] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 5] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 6] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 7] = *(mshabal_u32 *)(seed + o);
			t1.words[j + 0 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 1 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 2 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 3 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 4 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 5 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 6 + 64] = *(mshabal_u32 *)(zero + o);
			t1.words[j + 7 + 64] = *(mshabal_u32 *)(zero + o);
			// t2
			// (first 256bit skipped, will later be filled with data)
			t2.words[j + 0 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 1 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 2 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 3 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 4 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 5 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 6 + 64] = *(mshabal_u32 *)(seed + o);
			t2.words[j + 7 + 64] = *(mshabal_u32 *)(seed + o);
			// t3
			t3.words[j + 0] = *(mshabal_u32 *)(term + o);
			t3.words[j + 1] = *(mshabal_u32 *)(term + o);
			t3.words[j + 2] = *(mshabal_u32 *)(term + o);
			t3.words[j + 3] = *(mshabal_u32 *)(term + o);
			t3.words[j + 4] = *(mshabal_u32 *)(term + o);
			t3.words[j + 5] = *(mshabal_u32 *)(term + o);
			t3.words[j + 6] = *(mshabal_u32 *)(term + o);
			t3.words[j + 7] = *(mshabal_u32 *)(term + o);
			t3.words[j + 0 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 1 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 2 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 3 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 4 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 5 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 6 + 64] = *(mshabal_u32 *)(zero + o);
			t3.words[j + 7 + 64] = *(mshabal_u32 *)(zero + o);
		}

		shabal_context *init_x = new shabal_context[sizeof(shabal_context)];
		shabal_init(init_x, 256);
		mshabal256_context *init_mx = new mshabal256_context[sizeof(mshabal256_context)];
		mshabal256_init(init_mx, 256);

		for (unsigned long long n = 0; n < local_nonces;)
		{
			// iterate nonces (8 per cycle - avx2)
			// min 8 nonces left?
			if (n + 8 <= local_nonces)
			{
				//generate nonce numbers
				nonce1 = local_startnonce + n + 0;
				nonce2 = local_startnonce + n + 1;
				nonce3 = local_startnonce + n + 2;
				nonce4 = local_startnonce + n + 3;
				nonce5 = local_startnonce + n + 4;
				nonce6 = local_startnonce + n + 5;
				nonce7 = local_startnonce + n + 6;
				nonce8 = local_startnonce + n + 7;
				
				//kick nonce number into seed in t1 and t2


				//start rounds

				// 3 cases: first 128 rounds it is 1 or 2, after that 3
				// 1. unbroken message
				// 2. broken message
				// 3. unbroken message full length (4096 kib)

				// first 128 rounds
				for (size_t i = PLOT_SIZE; i > (PLOT_SIZE-HASH_CAP); i -= HASH_SIZE)
				{
					memcpy(mx, init_mx, sizeof(*init_mx));		// fast initialize shabal
					if (i % 64 == 0)							// Can msg be divided into 512bit packages without a reminder?
					{						
						//calc len
						//if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
						//else len = PLOT_SIZE + 16 - i;
						mshabal256_openclose_fast_even(&t1);			// last msg = seed + termination
					}
					else 
					{
						// kick 256 data reminder into smart termination string

						//calc len
						//if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
						//else len = PLOT_SIZE + 16 - i;

						mshabal256_openclose_fast_odd(&t2);				// last msg = 256 bit data + seed + termination
					}
				}
				// round 128-8192
				for (size_t i = PLOT_SIZE - HASH_CAP; i > 0; i -= HASH_SIZE)
				{
					// fast initialize shabal
					memcpy(mx, init_mx, sizeof(*init_mx));
					//calc len
					//if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
					//else len = PLOT_SIZE + 16 - i;
					simd256_mshabal_openclose_fast(&t3);				// last msg = termination

				}

				// generate final hash
				memcpy(mx, init_mx, sizeof(*init_mx));
				simd256_mshabal_openclose_fast(mx, &t3,gendata1, gendata2, gendata3, gendata4, gendata5, gendata6, gendata7, gendata8, 16 + PLOT_SIZE);

				// XOR with final TODO SIMD
				for (size_t i = 0; i < PLOT_SIZE; i++)
				{
					gendata1[i] ^= (final1[i % 32]);
					gendata2[i] ^= (final2[i % 32]);
					gendata3[i] ^= (final3[i % 32]);
					gendata4[i] ^= (final4[i % 32]);
					gendata5[i] ^= (final5[i % 32]);
					gendata6[i] ^= (final6[i % 32]);
					gendata7[i] ^= (final7[i % 32]);
					gendata8[i] ^= (final8[i % 32]);
				}

				// Sort them:  // optimised format - not needed at this point
				//for (size_t i = 0; i < HASH_CAP; i++)
				//{
//					memmove(&cache[i][(n + 0 + local_num*local_nonces) * SCOOP_SIZE], &gendata1[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 1 + local_num*local_nonces) * SCOOP_SIZE], &gendata2[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 2 + local_num*local_nonces) * SCOOP_SIZE], &gendata3[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 3 + local_num*local_nonces) * SCOOP_SIZE], &gendata4[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 4 + local_num*local_nonces) * SCOOP_SIZE], &gendata5[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 5 + local_num*local_nonces) * SCOOP_SIZE], &gendata6[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 6 + local_num*local_nonces) * SCOOP_SIZE], &gendata7[i * SCOOP_SIZE], SCOOP_SIZE);
					//memmove(&cache[i][(n + 7 + local_num*local_nonces) * SCOOP_SIZE], &gendata8[i * SCOOP_SIZE], SCOOP_SIZE);
				//}
				n += 8;
			}
			else
			{
				// if less than 8 nonces left, skip SIMD
				_mm256_zeroupper();
				nonce = local_startnonce + n;
				xv = reinterpret_cast<int8_t*>(&nonce);

				for (size_t i = 8; i < 16; i++)	gendata[PLOT_SIZE + i] = xv[15 - i];

				for (size_t i = PLOT_SIZE; i > 0; i -= HASH_SIZE)
				{
					memcpy(x, init_x, sizeof(*init_x)); // optimization: shabal_init(mx, 256);
					if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
					else len = PLOT_SIZE + 16 - i;

					shabal(x, &gendata[i], len);
					shabal_close(x, 0, 0, &gendata[i - HASH_SIZE]);
				}

				memcpy(x, init_x, sizeof(*init_x)); // optimization: shabal_init(mx, 256);
				shabal(x, gendata, 16 + PLOT_SIZE);
				shabal_close(x, 0, 0, final);

				// XOR with final
				for (size_t i = 0; i < PLOT_SIZE; i++)			gendata[i] ^= (final[i % HASH_SIZE]);

				// Sort them:
				for (size_t i = 0; i < HASH_CAP; i++)		memmove(&cache[i][(n + local_num*local_nonces) * SCOOP_SIZE], &gendata[i * SCOOP_SIZE], SCOOP_SIZE);
				n++;
			}
			worker_status[local_num] = n;
		}
		delete[] final;
		delete[] final1;
		delete[] final2;
		delete[] final3;
		delete[] final4;
		delete[] final5;
		delete[] final6;
		delete[] final7;
		delete[] final8;
		delete[] x;
		delete[] mx;
		delete[] init_mx;
		delete[] init_x;

		return;
	}
}
///////////////////////////////////////////////


namespace SSE4
{
	void work_i(const size_t local_num, unsigned long long loc_addr, const unsigned long long local_startnonce, const unsigned long long local_nonces)
	{
		unsigned long long nonce;
		unsigned long long nonce1;
		unsigned long long nonce2;
		unsigned long long nonce3;
		unsigned long long nonce4;

		char *final = new char[32];
		char *gendata = new char[16 + PLOT_SIZE];
		char *final1 = new char[32];
		char *final2 = new char[32];
		char *final3 = new char[32];
		char *final4 = new char[32];
		char *gendata1 = new char[16 + PLOT_SIZE];
		char *gendata2 = new char[16 + PLOT_SIZE];
		char *gendata3 = new char[16 + PLOT_SIZE];
		char *gendata4 = new char[16 + PLOT_SIZE];

		size_t len;
		shabal_context *x = new shabal_context[sizeof(shabal_context)];
		mshabal_context *mx = new mshabal_context[sizeof(mshabal_context)];

		int8_t *xv = reinterpret_cast<int8_t*>(&loc_addr); // optimization: reduced 8*4*nonces assignments
		for (size_t i = 0; i < 8; i++)
		{
			gendata[PLOT_SIZE + i] = xv[7 - i];
			gendata1[PLOT_SIZE + i] = xv[7 - i];
			gendata2[PLOT_SIZE + i] = xv[7 - i];
			gendata3[PLOT_SIZE + i] = xv[7 - i];
			gendata4[PLOT_SIZE + i] = xv[7 - i];
		}
		char *xv1, *xv2, *xv3, *xv4;

		shabal_context *init_x = new shabal_context[sizeof(shabal_context)];
		shabal_init(init_x, 256);
		mshabal_context *init_mx = new mshabal_context[sizeof(mshabal_context)];
		sse4_mshabal_init(init_mx, 256);

		for (unsigned long long n = 0; n < local_nonces;)
		{
			if (n + 4 <= local_nonces)
			{
				nonce1 = local_startnonce + n + 0;
				nonce2 = local_startnonce + n + 1;
				nonce3 = local_startnonce + n + 2;
				nonce4 = local_startnonce + n + 3;
				xv1 = reinterpret_cast<char*>(&nonce1);
				xv2 = reinterpret_cast<char*>(&nonce2);
				xv3 = reinterpret_cast<char*>(&nonce3);
				xv4 = reinterpret_cast<char*>(&nonce4);
				
				for (size_t i = 8; i < 16; i++)
				{
					gendata1[PLOT_SIZE + i] = xv1[15 - i];
					gendata2[PLOT_SIZE + i] = xv2[15 - i];
					gendata3[PLOT_SIZE + i] = xv3[15 - i];
					gendata4[PLOT_SIZE + i] = xv4[15 - i];
				}

				for (size_t i = PLOT_SIZE; i > 0; i -= HASH_SIZE)
				{
					memcpy(mx, init_mx, sizeof(*init_mx)); // optimization: sse4_mshabal_init(mx, 256);
					if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
					else len = PLOT_SIZE + 16 - i;
					sse4_mshabal(mx, &gendata1[i], &gendata2[i], &gendata3[i], &gendata4[i], len);
					sse4_mshabal_close(mx, 0, 0, 0, 0, 0, &gendata1[i - HASH_SIZE], &gendata2[i - HASH_SIZE], &gendata3[i - HASH_SIZE], &gendata4[i - HASH_SIZE]);
				}

				memcpy(mx, init_mx, sizeof(*init_mx)); // optimization: sse4_mshabal_init(mx, 256);
				sse4_mshabal(mx, gendata1, gendata2, gendata3, gendata4, 16 + PLOT_SIZE);
				sse4_mshabal_close(mx, 0, 0, 0, 0, 0, final1, final2, final3, final4);

				// XOR with final
				for (size_t i = 0; i < PLOT_SIZE; i++)
				{
					gendata1[i] ^= (final1[i % 32]);
					gendata2[i] ^= (final2[i % 32]);
					gendata3[i] ^= (final3[i % 32]);
					gendata4[i] ^= (final4[i % 32]);
				}

				// Sort them:
				for (size_t i = 0; i < HASH_CAP; i++)
				{
					memmove(&cache[i][(n + 0 + local_num*local_nonces) * SCOOP_SIZE], &gendata1[i * SCOOP_SIZE], SCOOP_SIZE);
					memmove(&cache[i][(n + 1 + local_num*local_nonces) * SCOOP_SIZE], &gendata2[i * SCOOP_SIZE], SCOOP_SIZE);
					memmove(&cache[i][(n + 2 + local_num*local_nonces) * SCOOP_SIZE], &gendata3[i * SCOOP_SIZE], SCOOP_SIZE);
					memmove(&cache[i][(n + 3 + local_num*local_nonces) * SCOOP_SIZE], &gendata4[i * SCOOP_SIZE], SCOOP_SIZE);
				}
				n += 4;
			}
			else
			{
				nonce = local_startnonce + n;
				xv = reinterpret_cast<int8_t*>(&nonce);

				for (size_t i = 8; i < 16; i++)	gendata[PLOT_SIZE + i] = xv[15 - i];

				for (size_t i = PLOT_SIZE; i > 0; i -= HASH_SIZE)
				{
					memcpy(x, init_x, sizeof(*init_x)); // optimization: shabal_init(x, 256);
					if (i < PLOT_SIZE + 16 - HASH_CAP) len = HASH_CAP;  // optimization: reduced 8064 assignments
					else len = PLOT_SIZE + 16 - i;

					shabal(x, &gendata[i], len);
					shabal_close(x, 0, 0, &gendata[i - HASH_SIZE]);
				}

				//shabal_init(x, 256);
				memcpy(x, init_x, sizeof(*init_x)); // optimization: shabal_init(x, 256);
				shabal(x, gendata, 16 + PLOT_SIZE);
				shabal_close(x, 0, 0, final);

				// XOR with final
				for (size_t i = 0; i < PLOT_SIZE; i++)			gendata[i] ^= (final[i % HASH_SIZE]);

				// Sort them:
				for (size_t i = 0; i < HASH_CAP; i++)		memmove(&cache[i][(n + local_num*local_nonces) * SCOOP_SIZE], &gendata[i * SCOOP_SIZE], SCOOP_SIZE);
				n++;
			}
			worker_status[local_num] = n;
		}
		delete[] final;
		delete[] gendata;
		delete[] gendata1;
		delete[] gendata2;
		delete[] gendata3;
		delete[] gendata4;
		delete[] final1;
		delete[] final2;
		delete[] final3;
		delete[] final4;
		delete[] x;
		delete[] mx;
		delete[] init_mx;
		delete[] init_x;

		return;
	}
}

