
#ifndef _RANDOM_H_
#define _RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif
	void random_byte(unsigned char * a_data_value, unsigned int a_data_len);
	void random_string(char * a_data_value, unsigned int a_data_len);
#ifdef __cplusplus
}
#endif

#endif /* _RANDOM_H_ */