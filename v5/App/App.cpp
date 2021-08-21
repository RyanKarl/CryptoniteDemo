/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX
#define BUFFER_SIZE 1200000
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <chrono>

using namespace std;

#define HASH_LEN 32
#define STRING_LEN 32
#define SIZEOF_SEED 4

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

unsigned char md_value_out[EVP_MAX_MD_SIZE];
unsigned int md_len_out;
int sha_index;

struct user_struct_out {
    uint32_t seed_out;
    int id_out;
    unsigned char rand_str_out[HASH_LEN] = {0};
    std::string rand_string_out = "";
    int plaintext;
    std::string ciphertext_string = "";
};

std::vector <user_struct_out> user_list_out;

void swap (int *a, int *b) { 
    int temp = *a; 
    *a = *b; 
    *b = temp; 
}
 
void printArray (int arr[], int n)
{
    for (int i = 0; i < n; i++)
        printf("%d ", arr[i]);
    
    printf("\n");
}

void sha_init(std::string s){

    char char_array[s.length()];

    int k;
    for (k = 0; k < sizeof(char_array); k++) {
        char_array[k] = s[k];
    }

    char_array[sizeof(char_array)] = '\0';

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    md = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, char_array, strlen(char_array));
    EVP_DigestFinal_ex(mdctx, md_value_out, &md_len_out);
    EVP_MD_CTX_free(mdctx);

}

void sha_hash(unsigned char *s, unsigned int s_len, int id){


    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    md = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, s, s_len);
    EVP_DigestFinal_ex(mdctx, md_value_out, &md_len_out);
    EVP_MD_CTX_free(mdctx);
    
    memcpy(user_list_out[id].rand_str_out, md_value_out, md_len_out);

}

bool isSmaller(string str1, string str2)
{
    int n1 = str1.length(), n2 = str2.length();
 
    if (n1 < n2)
        return true;
    if (n2 < n1)
        return false;
 
    for (int i = 0; i < n1; i++) {
        if (str1[i] < str2[i])
            return true;
        else if (str1[i] > str2[i])
            return false;
    }
    return false;
}


void reverse(string& str)
{
    int n = str.length();
 
    for (int i = 0; i < n / 2; i++)
        swap(str[i], str[n - i - 1]);
}


string findDiff(string str1, string str2)
{
    if (isSmaller(str1, str2))
        swap(str1, str2);
 
    string str = "";
 
    int n1 = str1.length(), n2 = str2.length();
    int diff = n1 - n2;
 
    int carry = 0;
 
    for (int i = n2 - 1; i >= 0; i--) {
        int sub = ((str1[i + diff] - '0') - (str2[i] - '0')
                   - carry);
        if (sub < 0) {
            sub = sub + 10;
            carry = 1;
        }
        else
            carry = 0;
 
        str.push_back(sub + '0');
    }
 
    for (int i = n1 - n2 - 1; i >= 0; i--) {
        if (str1[i] == '0' && carry) {
            str.push_back('9');
            continue;
        }
        int sub = ((str1[i] - '0') - carry);
        if (i > 0 || sub > 0) 
            str.push_back(sub + '0');
        carry = 0;
    }
 
    reverse(str);
 
    return str;
}


string findSum(string str1, string str2)
{
    if (str1.length() > str2.length())
        swap(str1, str2);

    string str = "";

    int n1 = str1.length(), n2 = str2.length();
    int diff = n2 - n1;

    int carry = 0;

    for (int i=n1-1; i>=0; i--)
    {
        int sum = ((str1[i]-'0') +
                   (str2[i+diff]-'0') +
                   carry);
        str.push_back(sum%10 + '0');
        carry = sum/10;
    }

    for (int i=n2-n1-1; i>=0; i--)
    {
        int sum = ((str2[i]-'0')+carry);
        str.push_back(sum%10 + '0');
        carry = sum/10;
    }

    if (carry)
        str.push_back(carry+'0');

    reverse(str);

    return str;
}


int leafVal = 0;
int faultCount = 0;
int faultLimit = 0;
int faultUpdateCounter = 1;
int keyCounter = 0;
std::vector<int> fault_list;

struct Node
{
	int key = 0;//id
        int fault = 0;
	string value = "0";
	struct Node *left;
	struct Node *right;
	int height = 0;
};

int height(struct Node *N)
{
	if (N == NULL)
		return 0;
	return N->height;
}

int max(int a, int b)
{
	return (a > b)? a : b;
}

struct Node* newNode(int key)
{
	struct Node* node = new Node();
	node->key = key;
	node->fault = 0;
        node->value = "0";
        node->left = NULL;
	node->right = NULL;
	node->height = 1; 
	leafVal++;
    return(node);
}

struct Node *rightRotate(struct Node *y)
{
	struct Node *x = y->left;
	struct Node *T2 = x->right;

	x->right = y;
	y->left = T2;

	y->height = max(height(y->left), height(y->right))+1;
	x->height = max(height(x->left), height(x->right))+1;

	return x;
}

struct Node *leftRotate(struct Node *x)
{
	struct Node *y = x->right;
	struct Node *T2 = y->left;

	y->left = x;
	x->right = T2;

	x->height = max(height(x->left), height(x->right))+1;
	y->height = max(height(y->left), height(y->right))+1;

	return y;
}

int getBalance(struct Node *N)
{
	if (N == NULL)
		return 0;
	return height(N->left) - height(N->right);
}

struct Node* insert(struct Node* node, int key)
{
	if (node == NULL)
		return(newNode(key));

	if (key < node->key)
		node->left = insert(node->left, key);
	else if (key > node->key)
		node->right = insert(node->right, key);
	else 
		return node;

	node->height = 1 + max(height(node->left),
						height(node->right));

	int balance = getBalance(node);


	if (balance > 1 && key < node->left->key)
		return rightRotate(node);

	if (balance < -1 && key > node->right->key)
		return leftRotate(node);

	if (balance > 1 && key > node->left->key)
	{
		node->left = leftRotate(node->left);
		return rightRotate(node);
	}

	if (balance < -1 && key < node->right->key)
	{
		node->right = rightRotate(node->right);
		return leftRotate(node);
	}

	return node;
}

void preOrder(struct Node *root)
{
	if(root != NULL)
	{
		printf("\nroot->key %d ", root->key);
        	printf("\nroot->fault %d ", root->fault);
        	cout << "\nvalue " << root->value << endl;
		printf("root->height %d \n", root->height);
		preOrder(root->left);
		preOrder(root->right);
	}
}

void getFaultList(struct Node *root)
{
       
	if(root != NULL)
        {
                if(root->fault == 1){
		    fault_list.push_back(root->key);
		}
                getFaultList(root->left);
                getFaultList(root->right);
        }
}


unsigned int getLeafCount(struct Node* node)
{
  if(node == NULL)      
    return 0;
  if(node->left == NULL && node->right==NULL){
      return 1;
  }               
  else
    return getLeafCount(node->left)+
           getLeafCount(node->right);     
}

void setFault(struct Node* node){

  if(node == NULL)      
    return;

  if(node->left == NULL && node->right == NULL){
      if(faultCount < faultLimit){
          faultCount++;
          node->fault = 1;
      }
      return;
  }               
  else{
    setFault(node->left);
    setFault(node->right);
  }    
}

void faultUpdate(struct Node *root)
{
    if(root == NULL){
        return;
    }
    
    if(root->left != NULL && root->right != NULL){
        if(root->left->fault == 1 && root->right->fault == 1){
            root->left->fault = 0;
            root->right->fault = 0;
            root->fault = 1;
            faultUpdateCounter = 1;
        }
    }
    
    faultUpdate(root->left);
    faultUpdate(root->right);
}


void sumUpdate(struct Node *root)
{
    if(root == NULL){
        return;
    }
    
    if(root->left != NULL && root->right != NULL){
    	    root->value = findSum(root->right->value, root->left->value);
    }
    
    sumUpdate(root->left);
    sumUpdate(root->right);
}


void keyUpdate(struct Node *root)
{
    if(root == NULL){
        return;
    }

    if(root->left == NULL && root->right == NULL){

	root->value = user_list_out[keyCounter].rand_string_out;
	
	keyCounter++;
    }

    keyUpdate(root->left);
    keyUpdate(root->right);
}


void randomize (int id, unsigned char* s, unsigned int s_len){

    sha_hash(s, s_len, id);
    user_list_out[id].rand_string_out = "";
    for(int j = 0; j < STRING_LEN; j++){
        user_list_out[id].rand_string_out += std::to_string(user_list_out[id].rand_str_out[j]);
    }
	
}

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
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
        print_error_message(ret);
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

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int num_users = atoi(argv[1]);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    struct user_struct_out temp_struct_out;
    uint32_t *seed_ptr = (uint32_t *) malloc(BUFFER_SIZE * sizeof(uint32_t));
    
    setup_phase(global_eid, seed_ptr, BUFFER_SIZE, num_users);   
    
    for(int i = 0; i < num_users; i++){
        temp_struct_out.seed_out = *(seed_ptr + i);
        temp_struct_out.id_out = i;
        temp_struct_out.plaintext = rand() % 10;
        sha_init(std::to_string(temp_struct_out.seed_out));	
        memcpy(temp_struct_out.rand_str_out, md_value_out, md_len_out);
	user_list_out.push_back(temp_struct_out);
    
    }
    
    int num_leaf = num_users;
    faultLimit = atoi(argv[2]);
    struct Node *root = NULL;
    int temp_id = 0;
    int tree_building_counter = 0;
    
    while(getLeafCount(root) != num_leaf){
	root = insert(root, tree_building_counter++);
    }
    setFault(root);

    faultUpdateCounter = 1;
    while(faultUpdateCounter != 0){
        faultUpdateCounter = 0;
        faultUpdate(root);
    }
    
    keyCounter = 0;
    
    keyUpdate(root);

    int sumUpdateCounter = root->height;     
    for(int i = 0; i < sumUpdateCounter; i++){
        sumUpdate(root);
    }

    for(int i = 0; i < num_users; i++){
    	randomize(i, user_list_out[i].rand_str_out, md_len_out);    
    } 

    keyCounter = 0;
    keyUpdate(root);
    sumUpdateCounter = root->height;
    for(int i = 0; i < sumUpdateCounter; i++){
        sumUpdate(root);
    }
    

    for(int i = 0; i < num_users; i++){
	user_list_out[i].ciphertext_string = findSum(user_list_out[i].rand_string_out, std::to_string(user_list_out[i].plaintext));
    } 


    string sum_string = "0";


    for(int i = faultLimit; i < num_users; i++){
        sum_string = findSum(sum_string, user_list_out[i].ciphertext_string);
    }

    getFaultList(root);
    
    
    compute_sum(global_eid, (char *) sum_string.c_str(), &fault_list[0], (sizeof(int) * fault_list.size()), (int)fault_list.size());
   
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    return 0;
}

