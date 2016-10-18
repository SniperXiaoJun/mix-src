#ifndef _GM_ECC_512_H
#define _GM_ECC_512_H

#define GM_ECC_512_BYTES_LEN			64


#include "gm-hash-bit.h"

#ifdef __cplusplus
extern "C" {
#endif


int tcm_gmecc512_init();


int tcm_gmecc512_release();


int tcm_gmecc512_encrypt(unsigned char *plaintext, unsigned int uPlaintextLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *ciphertext, unsigned int *puCiphertextLen);


int tcm_gmecc512_decrypt(unsigned char *ciphertext, unsigned int uCiphertextLen, unsigned char *prikey, unsigned int uPrikeyLen, unsigned char *plaintext, unsigned int *puPlaintextLen);

int tcm_gmecc512_get_usrinfo_value(unsigned char *userID, unsigned int uUserIDLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char digest[GM_ECC_512_BYTES_LEN],EHASH_TYPE hash_type);

int tcm_gmecc512_get_message_hash(unsigned char *msg, unsigned int msgLen, unsigned char  *userID, unsigned int uUserIDLen, 
	unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *digest, unsigned int *puDigestLen);

int tcm_gmecc512_signature( unsigned char *digest, unsigned int uDigestLen, unsigned char *prikey, unsigned int uPrikeyLen, /*out*/unsigned char *sig, /*out*/unsigned int *puSigLen);

int tcm_gmecc512_verify(unsigned char *digest, unsigned int uDigestLen, unsigned char *sig, unsigned int uSigLen, unsigned char *pubkey, unsigned int uPubkeyLen);

int tcm_gmecc512_exchange(unsigned char fA, unsigned char prikey_A[GM_ECC_512_BYTES_LEN], unsigned char pubkey_A[(GM_ECC_512_BYTES_LEN*2)+1], unsigned char prikey_RA[GM_ECC_512_BYTES_LEN], unsigned char pubkey_RA[(GM_ECC_512_BYTES_LEN*2)+1],
	unsigned char pubkey_B[(GM_ECC_512_BYTES_LEN*2)+1], unsigned char pubkey_RB[(GM_ECC_512_BYTES_LEN*2)+1], unsigned char Za[GM_ECC_512_BYTES_LEN], unsigned char Zb[GM_ECC_512_BYTES_LEN], /*out*/unsigned char key[16],
	/*out*/unsigned char S1[32], /*out*/unsigned char Sa[32], int keyLen);


// if success return 1, otherwise return 0.
unsigned char tcm_gmecc512_is_point_valid(unsigned char *point, unsigned int uPointLen);

// if success return 1, otherwise return 0.
unsigned char tcm_gmecc512_point_to_uncompressed(unsigned char *point, unsigned int uPointLen, unsigned char *uncompressedpoint, unsigned int *puUncompressedpointLen);


int tcm_gmecc512_genkey(unsigned char *prikey, unsigned int *puPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen);


int tcm_gmecc512_point_from_privatekey(const unsigned char *prikey, const unsigned int uPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen);


unsigned char tcm_gmecc512_is_key_match(const unsigned char *prikey, const unsigned int uPrikeyLen, const unsigned char *pubkey, const unsigned int uPubkeyLen);


#ifdef __cplusplus
}
#endif


#endif /* _GM_ECC_512_H */
