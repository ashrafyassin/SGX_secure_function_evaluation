
#include <stdarg.h>
#include <string.h>
#include <stdio.h>      /* vsnprintf */

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "enclave.h"
#include "enclave_t.h"  /* print_string */
#include <map>


#define SGX_IV_BITS 128
#define SGX_AES_BLOCK_SIZE 16

typedef long long int _8_Byte;

sgx_aes_ctr_128bit_key_t aes_key;
uint8_t iv[SGX_AES_BLOCK_SIZE];

sgx_ec256_private_t private_key;
sgx_ec256_public_t verify_key;

using namespace std;

//global map contains pairs of {client_id,client_sum}
map<unsigned int,unsigned int> my_map;
map<unsigned int,unsigned int> other_map;

//TODO delete printing
/* debug printing functions*/
void printf(const char *fmt, ...){
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_printf(buf);
}
void print_map(map<unsigned int,unsigned int> &mp){
	printf("printing the map\n");
	for(auto ele : mp){
		printf("%d,%d\n",ele.first,ele.second);
	}
}
void print_private_key(sgx_ec256_private_t &key){
	printf("printing private key\n");
	for(int i = 0; i < sizeof(key.r); i++){
		printf("%u,",key.r[i]);
	}
	printf("\n");
}
void print_pub_key(sgx_ec256_public_t &key){
	printf("printing public key\n");
	for(int i = 0; i < sizeof(key.gx); i++){
		printf("%u,",key.gx[i]);
	}
	printf("\n");
	for(int i = 0; i < sizeof(key.gy); i++){
		printf("%u,",key.gy[i]);
	}
	printf("\n");
}


/* Serialization helpers*/
int serialize_key(const sgx_ec256_public_t key, uint8_t* buf)
{
	if(!buf){
		return 1;
	}

    memcpy(buf, &key, sizeof(key));

    return 0;
}

int deserialize_key(sgx_ec256_public_t &key, const uint8_t* buf)
{
	if(!buf){
		return 1;
	}

    memcpy(&key, buf, sizeof(key));

    return 0;
}

int serialize_map(const map<unsigned int,unsigned int> &mp, uint8_t* stream)
{
	if(stream == NULL){
		return 1;
	}

	int i=0;
	_8_Byte id,sum;
	int elem_size = sizeof(_8_Byte);

	for(auto ele : mp)
	{
		id = ele.first;
		sum = ele.second;

		memcpy(stream+i,&id,elem_size);
		i+=elem_size;
		memcpy(stream+i,&sum,elem_size);
		i+=elem_size;
	}
	return 0;
}

int deserialize_map(map<unsigned int, unsigned int> &mp, const uint8_t* stream, size_t len)
{
	if (stream == NULL)
	{
		return 1;
	}

	_8_Byte id, sum;
	int elem_size = sizeof(_8_Byte);

	for(int i = 0 ; i < len; i+=2*elem_size)
	{
		memcpy(&id, stream+i, elem_size);
		memcpy(&sum, stream+i+elem_size, elem_size);

		mp.insert({(unsigned int)id,(unsigned int)sum});
	}
	return 0;
}


/*Authentication helpers*/
int sign_data(const uint8_t* data, uint8_t* signed_data, size_t data_len)
{
	if (!data || !signed_data || data_len == 0){
		return 1;
	}

	sgx_ecc_state_handle_t p_handle;
	sgx_ec256_signature_t p_signature;
	sgx_status_t ocall_status;


    ocall_status = sgx_ecc256_open_context(&p_handle);
    if (ocall_status) return 2;

    ocall_status = sgx_ecdsa_sign(data, data_len, &private_key, &p_signature, p_handle);
    if (ocall_status) return 3;

    size_t x_sign_size = sizeof(p_signature.x);
    size_t y_sign_size = sizeof(p_signature.y);

    memcpy(signed_data, data, data_len);
	memcpy(signed_data+data_len, p_signature.x, x_sign_size);
	memcpy(signed_data+data_len+x_sign_size, p_signature.y, y_sign_size);

    return 0;
}

int verify_sign(uint8_t* data, const uint8_t* signed_data, size_t signed_data_len)
{
	if (!data || !signed_data || signed_data_len == 0){
		return 1;
	}

   	uint8_t p_result;
   	sgx_status_t ocall_status;

	sgx_ecc_state_handle_t p_handle;
	sgx_ec256_signature_t p_signature;

    size_t x_sign_size = sizeof(p_signature.x);
    size_t y_sign_size = sizeof(p_signature.y);


	size_t data_len = signed_data_len - sizeof(p_signature);

    memcpy(data, signed_data, data_len);
	memcpy(p_signature.x, signed_data+data_len, x_sign_size);
	memcpy(p_signature.y, signed_data+data_len + x_sign_size, y_sign_size);

    ocall_status = sgx_ecc256_open_context(&p_handle);
    if (ocall_status) return 2;

    ocall_status = sgx_ecdsa_verify(data, data_len, &verify_key, &p_signature, &p_result, p_handle);
    if (ocall_status || p_result != 0) return 3;

    return 0;
}


/* ECALLS functions */
int ecall_init_signing_keys(const char* prv_file, const char* pub_file, const char* other_pub_file)
{
	sgx_ecc_state_handle_t p_handle;
    sgx_ec256_public_t p_public;

	sgx_status_t ocall_status;
	int ocall_ret;

    uint32_t unsealed_data_size = sizeof(private_key);
    uint32_t public_key_size = sizeof(p_public);

    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0,unsealed_data_size);
	if( sealed_data_size == UINT32_MAX) {
		return 1;
	}

	uint8_t sealed_data[sealed_data_size];
	uint8_t unsealed_data[unsealed_data_size];
	uint8_t serialized_key[public_key_size];


	//check if the private key exist and read it
	ocall_status = ocall_load_file_data(&ocall_ret, prv_file, sealed_data, sealed_data_size);
    if (ocall_status != SGX_SUCCESS){
    	return 2;
    }
    else if (ocall_ret == 0){
		// unseal the private key
	   	ocall_status = sgx_unseal_data((sgx_sealed_data_t *) sealed_data, NULL, NULL, private_key.r, &unsealed_data_size);
	    if (ocall_status) return 3;

    }
    else {
    	//create new key pair
    	ocall_status = sgx_ecc256_open_context(&p_handle);
	    if (ocall_status)return 4;

	    //create private & public key
	    ocall_status = sgx_ecc256_create_key_pair(&private_key, &p_public, p_handle);
	    if (ocall_status) return 5;

	    //TODO only this enclave should unseal it
		// seal the private key
	   	ocall_status = sgx_seal_data(0, NULL, sizeof(private_key),private_key.r, sealed_data_size, (sgx_sealed_data_t *) sealed_data);
	    if (ocall_status) return 6;

		//write the sealed private key to file
	    ocall_status = ocall_save_file_data(&ocall_ret, prv_file, sealed_data, sealed_data_size);
	    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) return 7;

	    //serialize key to be written to file
		int res = serialize_key(p_public, serialized_key);
		if (res != 0) return 8;

		//write the public key to file
		ocall_status = ocall_save_file_data(&ocall_ret, pub_file, serialized_key, public_key_size);
	    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) return 9;

	}

	//wait for the other public key file
	ocall_status = ocall_wait_for_ready_file(&ocall_ret,other_pub_file);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) return 10;

	//read the other public key
	ocall_status = ocall_load_file_data(&ocall_ret, other_pub_file, serialized_key, public_key_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) return 11;

    //deserialize key
	if (deserialize_key(verify_key, serialized_key) != 0) return 12;

	return 0;
}

int ecall_process_clients_file(const char* file_name,const size_t lines_num)
{
	sgx_status_t ocall_status;
	int ocall_ret;

	int id[lines_num], sum[lines_num];

	//line contains: id,sum
	ocall_status = ocall_read_line_data(&ocall_ret, file_name, id, sum, lines_num*sizeof(int));
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) return 1;

	for(int  i = 0; i < lines_num; i++){
		my_map.insert({(unsigned int)id[i],(unsigned int)sum[i]});
	}

	return 0;
}

int ecall_create_DH_keys(const char* my_key_file, const char* other_key_file)
{

    sgx_ecc_state_handle_t p_handle;
    sgx_ec256_private_t p_private;
    sgx_ec256_public_t p_public, p_public_ga;
    sgx_ec256_dh_shared_t p_shared_key;

	sgx_status_t ocall_status;
	int ocall_ret;

	size_t key_size = sizeof(p_public);
	uint8_t serialized_pub[key_size];

	size_t signed_data_size = sizeof(sgx_ec256_signature_t) + key_size;
	uint8_t signed_data[signed_data_size];

	//1.create DH private & public keys
    ocall_status = sgx_ecc256_open_context(&p_handle);
    if (ocall_status) return 1;

    ocall_status = sgx_ecc256_create_key_pair(&p_private, &p_public, p_handle);
    if (ocall_status) return 2;

    //serialize key for signing
	if (serialize_key(p_public,serialized_pub) != 0) return 3;

	//sign the key
	if (sign_data(serialized_pub, signed_data, key_size) != 0){
		return 4;
	}

    //2.write the signed public key to file
    ocall_status = ocall_save_file_data(&ocall_ret, my_key_file, signed_data, signed_data_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 5;
	}

	//3.wait for the other key file
	ocall_status = ocall_wait_for_ready_file(&ocall_ret,other_key_file);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 6;
	}

	//4.read the other public key
	uint8_t other_key[key_size];
	ocall_status = ocall_load_file_data(&ocall_ret, other_key_file, signed_data, signed_data_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 7;
	}

    //verify the signing on the key
	if(verify_sign(other_key, signed_data, signed_data_size) != 0){
		printf("error: DH key signature wasn't valid\n");
		return 8;
	}

	//remove the shared file after reading it
	ocall_status = ocall_remove_shared_file(&ocall_ret, other_key_file);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 9;
	}

	//5.deserialize the public key
	if(deserialize_key(p_public_ga, other_key) != 0) return 10;

    //6.create shared key
    ocall_status = sgx_ecc256_compute_shared_dhkey(&p_private,&p_public_ga,&p_shared_key,p_handle);
    if (ocall_status != SGX_SUCCESS){
        return 11;
    }

    ocall_status = sgx_ecc256_close_context(p_handle);
    if (ocall_status){
        return 12;
    }


    /*7.recommended: hash the shared key for symmetric encryption */

    sgx_sha_state_handle_t p_sha_handle;
    sgx_sha256_hash_t hash_res;

    ocall_status = sgx_sha256_init(&p_sha_handle);
	if (ocall_status != SGX_SUCCESS){
        return 13;
    }

    ocall_status = sgx_sha256_update(p_shared_key.s, sizeof(p_shared_key.s), p_sha_handle);
	if (ocall_status != SGX_SUCCESS){
        return 14;
    }

    ocall_status = sgx_sha256_get_hash(p_sha_handle,&hash_res);
	if (ocall_status != SGX_SUCCESS){
        return 15;
    }

    //aes_key[0-16] = hash[0-15]
    for(int i = 0 ; i < SGX_AESCTR_KEY_SIZE; i++){
    	aes_key[i] = hash_res[i];
    }

    //iv[0-16] = hash[16-31]
    for(int i = 0 ; i < SGX_AESCTR_KEY_SIZE; i++){
    	iv[i] = hash_res[SGX_AESCTR_KEY_SIZE+i];
    }

    return SGX_SUCCESS;
}

int ecall_encrypt_clients_data(const char* target_file)
{
	size_t data_size = my_map.size()*2*sizeof(_8_Byte);
	size_t signed_cipher_size = data_size + sizeof(sgx_ec256_signature_t);

	uint8_t plain_text[data_size];
	uint8_t cipher_text[data_size];

	sgx_status_t ocall_status;
	int ocall_ret;

	uint8_t session_iv[SGX_AES_BLOCK_SIZE];
	memcpy(session_iv, iv, SGX_AES_BLOCK_SIZE);

	//serilaize map to byte stream
	if(serialize_map(my_map, plain_text) != 0) return 1;

	//encrypt stream
	ocall_status = sgx_aes_ctr_encrypt(&aes_key, plain_text, data_size, session_iv, SGX_IV_BITS, cipher_text);
	if (ocall_status != SGX_SUCCESS){
		return 2;
	}

	//sign the encrypted stream
	uint8_t signed_cipher[signed_cipher_size];
	if (sign_data(cipher_text, signed_cipher, data_size) != 0){
		return 3;
	}

	//save signed and encrypted stream to shared file
	ocall_status = ocall_save_file_data(&ocall_ret, target_file, signed_cipher, signed_cipher_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 4;
	}

	return 0;
}

int ecall_decrypt_and_process_file(const char* target_file)
{
	sgx_status_t ocall_status;
	int ocall_ret;

	int len;

	//3.wait for file to be ready
 	ocall_status = ocall_wait_for_ready_file(&ocall_ret,target_file);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 1;
	}

	//3.get file lines num
 	ocall_status = ocall_get_file_size(&len,target_file);
	if (ocall_status != SGX_SUCCESS) {
		return 1;
	}

	int data_size = len - sizeof(sgx_ec256_signature_t);

	uint8_t sign_data[len];
	uint8_t plain_text[data_size];
	uint8_t cipher_text[data_size];

	uint8_t session_iv[SGX_AES_BLOCK_SIZE];
	memcpy(session_iv, iv, SGX_AES_BLOCK_SIZE);

	//read encrypted file
	ocall_status = ocall_load_file_data(&ocall_ret, target_file, sign_data, len);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 2;
	}

    //verify the signature
	if(verify_sign(cipher_text, sign_data, len) != 0){
		return 1;
	}

	//decrypt file
	ocall_status = sgx_aes_ctr_decrypt(&aes_key, cipher_text, data_size, session_iv, SGX_IV_BITS, plain_text);
	if (ocall_status != SGX_SUCCESS){
		return 3;
	}

	//deserialize decrypted stream to map
	if (deserialize_map(other_map, plain_text, data_size) != 0) return 4;

	//remove the shared file after reading it
	ocall_status = ocall_remove_shared_file(&ocall_ret, target_file);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 5;
	}

	return 0;
}

int ecall_calc_function()
{
	sgx_status_t ocall_status;
	int ocall_ret;

	int res = 0, count = 0, avg;

	for(auto elem : my_map){
		if(other_map.find(elem.first) != other_map.end()){
			res += elem.second;
			count++;
		}
	}

	avg = (count == 0 ? 0 : res/count);

	ocall_status = ocall_function_res(&ocall_ret, avg);
	if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
		return 1;
	}
	return 0;
}

