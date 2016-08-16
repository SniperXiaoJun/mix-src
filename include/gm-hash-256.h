
// gm-hash-256.h
#ifndef _GM_HASH_256_H_
#define _GM_HASH_256_H_


#define  GM_HASH_256_DIGEST_LEN     32

typedef struct {
	unsigned int total[2];
	unsigned int state[8];
	unsigned char buffer[64];
} gm_hash_256_context;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * 建立gm-hash-256 context
 * ctx gm-hash-256计算的上下文
 */
void gm_hash_256_starts(gm_hash_256_context *ctx );

/*
 * 提供输入数据
 * ctx gm-hash-256计算的上下文
 * input 输入数据
 * length 输入数据长度
 */
void gm_hash_256_update( gm_hash_256_context *ctx, unsigned char *input, unsigned int length);

/*
 * 计算结果
 * ctx gm-hash-256计算的上下文
 * digest 输出的Hash值
 */
void gm_hash_256_finish( gm_hash_256_context *ctx, unsigned char digest[32] );


/* 
 * 直接根据输入计算结果
 * datalen_in 输入数据长度
 * pdata_in 输入数据
 * digest 输出的Hash值
 */
int gm_hash_256_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[32]);


int gm_hash_256_hmac(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char digest[32]);

int gm_hash_256_kdf(/*out*/unsigned char *key, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen);


#ifdef __cplusplus
}
#endif

#endif /* gm-hash-256.h */
