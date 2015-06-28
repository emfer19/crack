/*
By: Zachary Corse
crack.exe
Multithreaded brute force password cracker.
Usage: ./crack NumberOfThreads SizeOfPassword Target
*/

/* gcc crack.c -o crack -lcrypt -lpthread
	./crack 1 3 po6bItRYyKfyg  */
	
#define _GNU_SOURCE
#include <crypt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <math.h>

char password[9] = "aaaaaaaa";	
pthread_mutex_t alock;			//global thread lock

typedef struct{
	int keysize;
	char *target;
	char *salt;
}passwordData;	//Used to store data for passwordLooper

void *passwordLooper(void *arg);

int main(int argc, char *argv[]){           /* usage = crack threads keysize target */
	int i = 0;
	/*  arg[0] = crack, arg[1] = #of threads arg[2] = size of password, 
	arg[3] = hashed password being cracked */

	if (argc !=  4) {
		fprintf(stderr, "Too few/many arguements give.\n");
		fprintf(stderr, "Proper usage: ./crack threads keysize target\n");
		exit(0);
	}

	int threads = *argv[1]-'0';         //threads is now equal to the second command line argument number
	int keysize = *argv[2]-'0';         //keysize is now equal to the third command line argument number
	char target[9]; 
	strcpy(target, argv[3]);
	char salt[10];

	while ( i < 2 ){            //Takes first two characters of the hashed password and assigns them to the salt variable
		salt[i] = target[i];
		i++;
	}

	printf("threads = %d\n", threads);      /*used for testing */
	printf("keysize = %d\n", keysize);
	printf("target = %s\n", target);        
	printf("salt = %s\n", salt);        
    
	if (threads < 1 || threads > 8){
		fprintf(stderr, "0 < threads <= 8\n");
		exit(0);
	}                                               /*Checks to be sure that threads and keysize are*/
	if (keysize < 1 || keysize > 8){                                                /*of the correct size   */
		fprintf(stderr, "0 < keysize <= 8\n");
		exit(0);
	}
	pthread_mutex_init(&alock, NULL);
	pthread_t t[threads];

	passwordData *pwd = (passwordData*) malloc(sizeof(passwordData));	

	pwd->keysize= keysize;
	pwd->target = target;
	pwd->salt = salt;
	
	for (i = 0; i < threads ; i++){
		pthread_create(&t[i], NULL, passwordLooper, (void*)pwd);
	}
	
	for (i = 0; i < threads; i++){
		pthread_join(t[i],NULL);
	}
	
}

/*_______________________________________________________________________*/
void *passwordLooper(void *arg){
	passwordData *pwd = (passwordData *)arg;
	int result;
	
	struct crypt_data data;		//Data structure for crypt_r
	data.initialized = 0;			//Initialized to zero
	
	int level = 0; 
	int ks = pwd->keysize;
	
	password[ks] = 0;
	char localpw[9];
	
	char *target = pwd->target;
	char *s = pwd->salt;
	
	//Checks possible passwords
	while (level < ks){
		level = 0;
		
		pthread_mutex_lock(&alock);	//Locking
		
		while (level < ks) {
			if (password[level] >= 'a' && password[level] < 'z'){
				password[level]++;
				break;
			}
			if (password[level] == 'z'){
				password[level] = 'a';
				level++;
			}
		}
		
		strcpy(localpw, password);
		pthread_mutex_unlock(&alock);	//Unlocking
		
		if (strcmp( crypt_r(localpw, s, &data), target ) == 0){
			printf("password found!\n");
			printf("Password = %s\n", localpw);
			exit(0);
		}
	}

        if (level >= ks){//if level ends up bigger than the keysize, break, no longer checking for passwords
		printf("Password not found\n");
		exit(0);
        }
	return 0;
}