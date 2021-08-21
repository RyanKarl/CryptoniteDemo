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

//#include <stdarg.h>
//#include <stdio.h>      /* vsnprintf */
#include <string>
//#include <string.h>
#include <sgx_trts.h>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <vector>
#include <openssl/evp.h>
//#include <iostream>
//#include "sgx_tcrypto.h"
#define HASH_LEN 32
#define STRING_LEN 32
#define SIZEOF_SEED 4

//using namespace std;

//Store user data
struct user_struct {

    unsigned char rand_str[HASH_LEN] = {0};

};

std::vector <user_struct> user_list;
unsigned char md_value[EVP_MAX_MD_SIZE];
unsigned int md_len;
int sha_index;

//Initialize Random String
void sha_init(std::string s){

    //Convert to array of char for OpenSSL
    char char_array[s.length()];
    int k;
    for (k = 0; k < sizeof(char_array); k++) {
        char_array[k] = s[k];
    }

    char_array[sizeof(char_array)] = '\0';

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    //Perform Cryptographic Hash (stored in md_value)
    md = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, char_array, strlen(char_array));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

}

//Update Random String
void sha_hash(unsigned char *s, unsigned int s_len, int id){

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    //Perform Cryptographic Hash (stored in md_value)
    md = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, s, s_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    memcpy(user_list[id].rand_str, md_value, md_len);

}


bool isSmaller(std::string str1, std::string str2)
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


void reverse(std::string& str)
{
    int n = str.length();
 
    for (int i = 0; i < n / 2; i++)
        std::swap(str[i], str[n - i - 1]);
}


std::string findDiff(std::string str1, std::string str2)
{
    if (isSmaller(str1, str2))
        swap(str1, str2);
 
    std::string str = "";
 
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


std::string findSum(std::string str1, std::string str2)
{
    if (str1.length() > str2.length())
        swap(str1, str2);

    std::string str = "";

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
std::vector<int> faultNodes;
struct Node *root_enclave = NULL;
std::string final_sum = "0";
int break_recursion = 0;

struct Node
{
	int key = 0;//id
        int fault = 0;
	std::string value = "0";
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
	node->height = 1; // new node is initially added at leaf
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

	node->height = 1 + max(height(node->left), height(node->right));

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
        	const char* temp_value = root->value.c_str();
		
		preOrder(root->left);
		preOrder(root->right);
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
        sha_hash(user_list[keyCounter].rand_str, HASH_LEN, keyCounter);
	root->value = "";
	for(int j = 0; j < STRING_LEN; j++){
	    root->value += std::to_string(user_list[keyCounter].rand_str[j]);//user_list[keyCounter].rand_string;
	}
	keyCounter++;
    }

    keyUpdate(root->left);
    keyUpdate(root->right);
}


void faultRecover(struct Node *root, int fault_id)
{
	if(root == NULL){
            return;
        }
	if(root != NULL){
		
	    if(fault_id == root->key){
                final_sum = findSum(final_sum, root->value);
                break_recursion = 1;	        
	    }
	}        
        if(break_recursion == 0){	
	    faultRecover(root->left, fault_id);
            faultRecover(root->right, fault_id);
	}
	else{
	    return;
	}
}

void swap (int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

//Initialize Enclave with seeds and random mappings
void setup_phase(uint32_t *p_return_ptr, size_t len, int num)
{

    user_struct temp_struct;   
    uint32_t *p_ints = (uint32_t *) malloc(len*sizeof(uint32_t));
    uint32_t r;

    for(int i = 0; i < num; i++){
        
	//Get random seed	
	sgx_read_rand((unsigned char *) &r, sizeof(uint32_t));

	//Generate random string	
        sha_init(std::to_string(r));	   
        memcpy(temp_struct.rand_str, md_value, md_len);
        
	user_list.push_back(temp_struct);
        p_ints[i] = r;
    }

    int num_leaf = num;
    int temp_id = 0;
    int tree_building_counter = 0;
    //Constructing tree
    int counter_debug = 0;
    while(getLeafCount(root_enclave) != num_leaf){
	    root_enclave = insert(root_enclave, tree_building_counter++);
    }

    //Assign key_points to tree leaves
    keyUpdate(root_enclave);
    int sumUpdateCounter = root_enclave->height;

    for(int i = 0; i < sumUpdateCounter; i++){
        sumUpdate(root_enclave);
    }
     
    keyCounter = 0;
    keyUpdate(root_enclave);
    sumUpdateCounter = root_enclave->height;

    for(int i = 0; i < sumUpdateCounter; i++){
        sumUpdate(root_enclave);
    }
    
    memcpy(p_return_ptr, p_ints, len);
    free(p_ints);

    return;

}

void compute_sum(char *str, int *fault_arr, size_t len, int num_faults){

    final_sum = str;

    if(num_faults > 0){
        for(int i = 0; i < num_faults; i++){
	    faultRecover(root_enclave, fault_arr[i]);
	}
    }

    final_sum = findDiff(final_sum, root_enclave->value);


    return;
}

