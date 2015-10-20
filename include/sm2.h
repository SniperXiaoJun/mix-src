#ifndef _SM2_H
#define _SM2_H

#define SM2_BYTES_LEN			32

#ifdef __cplusplus
extern "C" {
#endif


int tcm_ecc_init();


int tcm_ecc_release();


int tcm_ecc_encrypt(unsigned char *plaintext, unsigned int uPlaintextLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *ciphertext, unsigned int *puCiphertextLen);


int tcm_ecc_decrypt(unsigned char *ciphertext, unsigned int uCiphertextLen, unsigned char *prikey, unsigned int uPrikeyLen, unsigned char *plaintext, unsigned int *puPlaintextLen);

int tcm_get_usrinfo_value(unsigned char *userID, unsigned int uUserIDLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char digest[32]);

int tcm_get_message_hash(unsigned char *msg, unsigned int msgLen, unsigned char  *userID, unsigned int uUserIDLen, 
	unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *digest, unsigned int *puDigestLen);

int tcm_ecc_signature( unsigned char *digest, unsigned int uDigestLen, unsigned char *prikey, unsigned int uPrikeyLen, /*out*/unsigned char *sig, /*out*/unsigned int *puSigLen);

int tcm_ecc_verify(unsigned char *digest, unsigned int uDigestLen, unsigned char *sig, unsigned int uSigLen, unsigned char *pubkey, unsigned int uPubkeyLen);

int tcm_ecc_exchange(unsigned char fA, unsigned char prikey_A[32], unsigned char pubkey_A[65], unsigned char prikey_RA[32], unsigned char pubkey_RA[65],
	unsigned char pubkey_B[65], unsigned char pubkey_RB[65], unsigned char Za[32], unsigned char Zb[32], /*out*/unsigned char key[16],
	/*out*/unsigned char S1[32], /*out*/unsigned char Sa[32]);


// if success return 1, otherwise return 0.
unsigned char tcm_ecc_is_point_valid(unsigned char *point, unsigned int uPointLen);

// if success return 1, otherwise return 0.
unsigned char tcm_ecc_point_to_uncompressed(unsigned char *point, unsigned int uPointLen, unsigned char *uncompressedpoint, unsigned int *puUncompressedpointLen);


int tcm_ecc_genkey(unsigned char *prikey, unsigned int *puPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen);


int tcm_ecc_point_from_privatekey(const unsigned char *prikey, const unsigned int uPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen);


unsigned char tcm_ecc_is_key_match(const unsigned char *prikey, const unsigned int uPrikeyLen, const unsigned char *pubkey, const unsigned int uPubkeyLen);


#ifdef __cplusplus
}
#endif


#endif /* _SM2_H */
