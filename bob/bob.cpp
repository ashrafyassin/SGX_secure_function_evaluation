#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>

#include <sgx_urts.h>
#include "bob.h"

#include "enclave_u.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* files for IPC between enclaves with */
#define ALICE_DH_KEY_FILE "../alice_DH_key"
#define BOB_DH_KEY_FILE "../bob_DH_key"

#define ALICE_CLIENTS_FILE "../alice_secret_clients"
#define BOB_CLIENTS_FILE "../bob_secret_clients"

#define BOB_PRIVATE_FILE "../bob_prv_key"
#define BOB_VERIFY_KEY_FILE "../bob_pub_key"

#define ALICE_VERIFY_KEY_FILE "../alice_pub_key"

#define MAX_PATH FILENAME_MAX

using namespace std;

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        if (fp != NULL) fclose(fp);

        return -1;
    }
    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);



    return 0;
}

int get_file_lines_num(const char* file_name)
{
    int count = 0;
    string line;

    ifstream file(file_name);

    while (getline(file, line))
        count++;

    return count;
}

/* OCall functions */
void ocall_printf(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

int ocall_wait_for_ready_file(const char* file_name)
{
    int counter = 0;
    bool res = 0;

    while(!res){

        ifstream f(file_name);
        res = f.good();

        counter++;
        if(counter >= 10){
            printf("the file %s wasn't available for %d seconds\n",file_name,counter);
            return 1;
        }

        sleep(1);
    }
    return 0;
}

int ocall_get_file_size(const char* file_name)
{
    ifstream f(file_name, std::ifstream::ate | std::ifstream::binary);

    return f.tellg();
}

int ocall_save_file_data(const char* file_name, const uint8_t* data, const size_t len)
{
    ofstream file(file_name, ios::out | ios::binary);

    if (file.fail()) {
    	return 1;
    }

    file.write((const char*) data, len);

    file.close();
    return 0;
}

int ocall_load_file_data(const char* file_name, uint8_t* data, const size_t len)
{
    ifstream file(file_name, ios::in | ios::binary);

    if (file.fail()) {
    	return 1;
    }
    file.read((char*) data, len);

    file.close();
    return 0;
}

int ocall_read_line_data(const char* file_name, int* a, int* b, const size_t len)
{
    int i = 0;

    ifstream file(file_name);

    while(file >> a[i] >> b[i]) i++;

    return 0 ;
}

int ocall_remove_shared_file(const char* file_name)
{
    return remove(file_name);
}

int ocall_function_res(int avg)
{
    printf("Bob average is: %d\n",avg);
    return 0;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t ecall_status;
    int ecall_return = 0;

    /* Changing dir to where the executable is.*/
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    if(argc < 2)
        abort();

    ptr = realpath(dirname(argv[0]),absolutePath);
    if( chdir(absolutePath) != 0)
            abort();


/********************************** 1. Initialize the enclave **********************************/
    if(initialize_enclave() < 0){
        printf("Initializing the enclave failed \n");
        return -1;
    }


/********************************** 2. Initialize signing keys **********************************/
    ecall_status = ecall_init_signing_keys(global_eid, &ecall_return, BOB_PRIVATE_FILE, BOB_VERIFY_KEY_FILE, ALICE_VERIFY_KEY_FILE);
    if (ecall_status != SGX_SUCCESS)
        abort();

    if (ecall_return != 0) {
        printf("initializing signing keys failed %d \n", ecall_return);
    }


/******************************* 3. Pass clients file to enclave *******************************/
    char* clients_file = (char*)argv[1];
    size_t file_lines_num = get_file_lines_num(clients_file);

    ecall_status = ecall_process_clients_file(global_eid, &ecall_return,clients_file,file_lines_num);
    if (ecall_status != SGX_SUCCESS)
        abort();

    if (ecall_return != 0) {
        printf("processing bob clients file failed %d \n", ecall_return);
    }


/************************************* 4. Agree on DH keys *************************************/
    ecall_status = ecall_create_DH_keys(global_eid, &ecall_return, BOB_DH_KEY_FILE, ALICE_DH_KEY_FILE);
    if (ecall_status != SGX_SUCCESS)
        abort();

    if (ecall_return != 0) {
        printf("creating DH keys failed %d \n", ecall_return);
        return -1;
    }


/************************** 5. Encrypt client data with the shared key **************************/
    ecall_status = ecall_encrypt_clients_data(global_eid, &ecall_return,BOB_CLIENTS_FILE);
    if (ecall_status != SGX_SUCCESS)
        abort();

    if (ecall_return != 0) {
        printf("encrypting bob clients failed %d \n", ecall_return);
        return -1;
    }


/************************** 6. Pass the other side's encrypted clients **************************/
    ecall_status = ecall_decrypt_and_process_file(global_eid, &ecall_return,ALICE_CLIENTS_FILE);
    if (ecall_status != SGX_SUCCESS)
        abort();

    if (ecall_return != 0) {
        printf("decryption failed %d \n", ecall_return);
        return -1;
    }


/******************************* 7. Calculate the function result *******************************/
    ecall_status = ecall_calc_function(global_eid, &ecall_return);
    if (ecall_status != SGX_SUCCESS)
        abort();

    if (ecall_return != 0) {
        printf("calculating function failed %d \n", ecall_return);
        return -1;
    }


/*********************************** 8. Destroy enclave *****************************************/
    sgx_destroy_enclave(global_eid);

    return 0;
}

