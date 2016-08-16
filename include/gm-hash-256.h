
// sm3.h
#ifndef _GM_HASH_256_H_
#define _GM_HASH_256_H_


#define  GM_HASH_256_DIGEST_LEN     32

typedef struct {
	unsigned int total[2];
	unsigned int state[8];
	unsigned char buffer[64];
} sch_context;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * ����SM3 context
 * ctx SM3�����������
 */
void gm_hash_256_starts(sch_context *ctx );

/*
 * �ṩ��������
 * ctx SM3�����������
 * input ��������
 * length �������ݳ���
 */
void gm_hash_256_update( sch_context *ctx, unsigned char *input, unsigned int length);

/*
 * ������
 * ctx SM3�����������
 * digest �����Hashֵ
 */
void gm_hash_256_finish( sch_context *ctx, unsigned char digest[32] );


/* 
 * ֱ�Ӹ������������
 * datalen_in �������ݳ���
 * pdata_in ��������
 * digest �����Hashֵ
 */
int gm_hash_256_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[32]);


int gm_hash_256_hmac(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char digest[32]);

int gm_hash_256_kdf(/*out*/unsigned char *key, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen);


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
