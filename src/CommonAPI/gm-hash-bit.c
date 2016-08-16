
// gm-hash-bit.c
#include "gm-hash-bit.h"

#ifdef _WINDOWS
#include <windows.h>
#endif

#include <string.h>
#include <stdio.h>
#include "o_all_type_def.h"



/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned int) (b)[(i)    ] << 24 )        \
        | ( (unsigned int) (b)[(i) + 1] << 16 )        \
        | ( (unsigned int) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned int) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23))


void gm_hash_starts(gm_hash_context *ctx ) 
{
	if(!ctx)
		return;

	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x7380166F;
	ctx->state[1] = 0x4914B2B9;
	ctx->state[2] = 0x172442D7;
	ctx->state[3] = 0xDA8A0600;
	ctx->state[4] = 0xA96F30BC;
	ctx->state[5] = 0x163138AA;
	ctx->state[6] = 0xE38DEE4D;
	ctx->state[7] = 0xB0FB0E4E;
}

// data: 64 bytes
static void gm_hash_process(gm_hash_context *ctx, const unsigned char *data) 
{
	unsigned int SS1, SS2, TT1, TT2, W[68], W1[64];
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int T[64];
	unsigned int Temp1, Temp2, Temp3, Temp4, Temp5;
	int j;
#ifdef _DEBUG
	int i;
#endif

	if(!ctx || !data)
		return;

	for (j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for (j = 16; j < 64; j++)
		T[j] = 0x7A879D8A;

	GET_ULONG_BE( W[ 0], data, 0);
	GET_ULONG_BE( W[ 1], data, 4);
	GET_ULONG_BE( W[ 2], data, 8);
	GET_ULONG_BE( W[ 3], data, 12);
	GET_ULONG_BE( W[ 4], data, 16);
	GET_ULONG_BE( W[ 5], data, 20);
	GET_ULONG_BE( W[ 6], data, 24);
	GET_ULONG_BE( W[ 7], data, 28);
	GET_ULONG_BE( W[ 8], data, 32);
	GET_ULONG_BE( W[ 9], data, 36);
	GET_ULONG_BE( W[10], data, 40);
	GET_ULONG_BE( W[11], data, 44);
	GET_ULONG_BE( W[12], data, 48);
	GET_ULONG_BE( W[13], data, 52);
	GET_ULONG_BE( W[14], data, 56);
	GET_ULONG_BE( W[15], data, 60);

#ifdef _DEBUG
	printf("Message with padding:\n");
	for(i=0; i< 8; i++)
	printf("%08x ",W[i]);
	printf("\n");
	for(i=8; i< 16; i++)
	printf("%08x ",W[i]);
	printf("\n");
#endif

	for (j = 16; j < 68; j++) 
	{
		Temp1 = W[j - 16] ^ W[j - 9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 = ROTL(W[j - 13],7 ) ^ W[j - 6];
		W[j] = Temp4 ^ Temp5;
	}

#ifdef _DEBUG
	printf("Expanding message W0-67:\n");
	for(i=0; i<68; i++)
	{
		printf("%08x ",W[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	for (j = 0; j < 64; j++) 
	{
		W1[j] = W[j] ^ W[j + 4];
	}

#ifdef _DEBUG
	printf("Expanding message W'0-63:\n");
	for(i=0; i<64; i++)
	{
		printf("%08x ",W1[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];
#ifdef _DEBUG
	printf("j     A       B        C         D         E        F        G       H\n");
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);
#endif

	for (j = 0; j < 16; j++) 
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef _DEBUG
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}

	for (j = 16; j < 64; j++) 
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef _DEBUG
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}

	ctx->state[0] ^= A;
	ctx->state[1] ^= B;
	ctx->state[2] ^= C;
	ctx->state[3] ^= D;
	ctx->state[4] ^= E;
	ctx->state[5] ^= F;
	ctx->state[6] ^= G;
	ctx->state[7] ^= H;
#ifdef _DEBUG
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",ctx->state[0],ctx->state[1],ctx->state[2],
			ctx->state[3],ctx->state[4],ctx->state[5],ctx->state[6],ctx->state[7]);
#endif

}

void gm_hash_update( gm_hash_context *ctx, unsigned char *input, unsigned int length)
{
	int fill;
	unsigned int left;

	if(!ctx || !input || (length<=0))
		return;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += length;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < (unsigned int) length)
		ctx->total[1]++;

	if (left && (length >= (unsigned int)fill) )
	{
		memcpy((void *) (ctx->buffer + left), (void *) input, fill);
		gm_hash_process(ctx, ctx->buffer);
		input += fill;
		length -= fill;
		left = 0;
	}

	while (length >= 64) 
	{
		gm_hash_process(ctx, input);
		input += 64;
		length -= 64;
	}

	if (length > 0)
	{
		memcpy((void *) (ctx->buffer + left), (void *) input, length);
	}
}

static const unsigned char gm_hash_padding[64] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0 };



void gm_hash_finish( gm_hash_context *ctx, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type) 
{
	unsigned int last, padn;
	unsigned int high, low;
	unsigned char msgLen[8];

	if(!ctx )
		return;

	high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
	low = (ctx->total[0] << 3);

	PUT_ULONG_BE( high, msgLen, 0);
	PUT_ULONG_BE( low, msgLen, 4);

	last = ctx->total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	gm_hash_update(ctx, (unsigned char *) gm_hash_padding, padn);
	gm_hash_update(ctx, msgLen, 8);

	PUT_ULONG_BE( ctx->state[0], digest, 0);
	PUT_ULONG_BE( ctx->state[1], digest, 4);
	PUT_ULONG_BE( ctx->state[2], digest, 8);
	PUT_ULONG_BE( ctx->state[3], digest, 12);
	PUT_ULONG_BE( ctx->state[4], digest, 16);
	PUT_ULONG_BE( ctx->state[5], digest, 20);
	PUT_ULONG_BE( ctx->state[6], digest, 24);
	PUT_ULONG_BE( ctx->state[7], digest, 28);

	switch(hash_type)
	{
	case EHASH_TYPE_SM3:
		{
			// 
		}
		break;
	case EHASH_TYPE_ZY_HASH_256:
		{
			int i = 0;

			for(i = 0; i < GM_HASH_BYTES_LEN; i++)
			{
				digest[i] = digest[i] ^ (unsigned char)GM_HASH_256_BYTES_XOR[i];
			}
		}
		break;
	case EHASH_TYPE_ZY_HASH_512:
		{
			int i = 0;

			for(i = 0; i < GM_HASH_BYTES_LEN; i++)
			{
				digest[i] = digest[i] ^ (unsigned char)GM_HASH_512_BYTES_XOR[i];
			}

			gm_hash_hash(GM_HASH_BYTES_LEN,digest,digest+32,EHASH_TYPE_SM3);
		}
		break;
	}
}


int gm_hash_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type) 
{
	gm_hash_context ctx;

	if( (datalen_in>0) && (!pdata_in) )
		return OPE_ERR_INVALID_PARAM;

	gm_hash_starts(&ctx);
	gm_hash_update(&ctx, pdata_in, datalen_in);
	gm_hash_finish(&ctx, digest,hash_type);

	memset(&ctx, 0, sizeof(gm_hash_context));

	return 0;
}


#define HAMC_PAD_LEN  64
// reference: rfc2104
int gm_hash_hmac(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type)
{
	gm_hash_context ctx;
	unsigned char k_ipad[HAMC_PAD_LEN], k_opad[HAMC_PAD_LEN];
	unsigned char tk[GM_HASH_MAX_BYTES_LEN];
	unsigned char temp_digest[GM_HASH_MAX_BYTES_LEN];
	int i;

	if(!key)
		return OPE_ERR_INVALID_PARAM;

	if(key_len > HAMC_PAD_LEN)
	{
		gm_hash_hash(key_len, key, tk, hash_type);
		key = tk;
		switch(hash_type)
		{
		case EHASH_TYPE_SM3:
			key_len = GM_HASH_256_BYTES_LEN;
			break;
		case EHASH_TYPE_ZY_HASH_256:
			key_len = GM_HASH_256_BYTES_LEN;
			break;
		case EHASH_TYPE_ZY_HASH_512:
			key_len = GM_HASH_512_BYTES_LEN;
			break;
		}
	}

	memset(k_ipad, 0x00, sizeof(k_ipad));
	memset(k_opad, 0x00, sizeof(k_opad));

	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	for(i=0; i<HAMC_PAD_LEN; i++)
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5C;
	}

	memset(&ctx,0x00,sizeof(ctx));

	gm_hash_starts(&ctx);
	gm_hash_update(&ctx, k_ipad, HAMC_PAD_LEN);
	gm_hash_update(&ctx, text, text_len);
	gm_hash_finish(&ctx, temp_digest, hash_type);

	memset(&ctx,0x00,sizeof(ctx));

	gm_hash_starts(&ctx);
	gm_hash_update(&ctx, k_opad, HAMC_PAD_LEN);
	gm_hash_update(&ctx, temp_digest, GM_HASH_MAX_BYTES_LEN);
	gm_hash_finish(&ctx, digest, hash_type);

	return 0;
}


int gm_hash_kdf(/*out*/unsigned char *key, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen, EHASH_TYPE hash_type)
{
	int count, ctIndex;
	gm_hash_context ctx;
	unsigned char zBuf[4];
	unsigned char temp_digest[GM_HASH_MAX_BYTES_LEN];
	int gm_hash_bytes_len = 0;

	if( (!key) || (klen <0 ) )
		return OPE_ERR_INVALID_PARAM;

	if(0 == klen)
		return 0;

	switch(hash_type)
	{
	case EHASH_TYPE_SM3:
		gm_hash_bytes_len = GM_HASH_256_BYTES_LEN;
		break;
	case EHASH_TYPE_ZY_HASH_256:
		gm_hash_bytes_len = GM_HASH_256_BYTES_LEN;
		break;
	case EHASH_TYPE_ZY_HASH_512:
		gm_hash_bytes_len = GM_HASH_512_BYTES_LEN;
		break;
	}

	count=klen / gm_hash_bytes_len;

	if(klen % gm_hash_bytes_len)
		count++ ;

	for(ctIndex=1; ctIndex <= count; ctIndex++)
	{
		memset(&ctx,0x00,sizeof(ctx));

		PUT_ULONG_BE(ctIndex,zBuf,0);

		gm_hash_starts(&ctx);
		gm_hash_update(&ctx, z, zlen);
		gm_hash_update(&ctx, zBuf, sizeof(zBuf));
		gm_hash_finish(&ctx, temp_digest, hash_type);

		if( (ctIndex == count) && (klen % gm_hash_bytes_len) )
			memcpy(&key[(ctIndex-1) * gm_hash_bytes_len], temp_digest, klen % gm_hash_bytes_len);
		else
			memcpy(&key[(ctIndex-1) * gm_hash_bytes_len], temp_digest, gm_hash_bytes_len);
	}

	return 0;
}

