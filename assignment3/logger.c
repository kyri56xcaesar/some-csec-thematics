#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include "logger.h"
#include <errno.h>
#include <gmp.h>
#include <inttypes.h>
#include "encryption/util.h"

#define MAX_BUFFER 4096
#define MAX_CIPHER 16384

#define PRIME1 17
#define PRIME2 29


void key_generation();
void encryption();
void decryption();
size_t* encrypt(size_t* cipher, char *plaintext, int size, mpz_t puKey, mpz_t n);
char* decrypt(mpz_t prKey, mpz_t n);
void destruct();



const char *LOG_FILE_NAME ="file_logging.log";

mpz_t n;    // mpz_t type number to hold n key
mpz_t d;    // mpz_t type number to hold d key
mpz_t e;    // mpz_t type number to hold e key
char *k;    // string to hold given key path
char *in = "file_logging.log";   // string to hold given input path
char *out = "enc_file_logging.log";  // string to hold given output path


// a file that is gonna be written, must be opened first. Therefore 
// whenever a file is opened, save a reference of its path in order to keep it
// for the write log.
char file_opened[100];


int file_exists(const char *filename)
{
	struct stat buffer;
	
	return stat(filename, &buffer) == 0 ? 1 : 0;
}

char *file_fingerprint(char *file_name)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	int i;
	MD5_CTX mdContext;
	int bytes=0;
	unsigned char data[1024];
	char *filemd5 = (char*)malloc(33 *sizeof(char));

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(file_name, "rb"); 

	if (original_fopen_ret == NULL)
	{
		perror("error openning file");
	}

	MD5_Init(&mdContext);

	while ((bytes = fread(data, 1, 1024, original_fopen_ret)) != 0)
	{
		MD5_Update(&mdContext, data, bytes);
	}

	MD5_Final(c, &mdContext);

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		sprintf(&filemd5[i*2], "%02x", (unsigned int)c[i]);
	}

	printf("calculated md5:%s ", filemd5);
	printf("%s\n", file_name);

	fclose(original_fopen_ret);
	return filemd5;
}

int check_if_empty_file(char *path)
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, "r");

	if (original_fopen_ret == NULL)
	{
		perror("error opening file");
	}

	fseek(original_fopen_ret, 0, SEEK_END);

	if (ftell(original_fopen_ret) == 0)	
	{
		fclose(original_fopen_ret);
		return 1;
	}
	fclose(original_fopen_ret);
	return 0;

}

int join_string_at(char *src, char *str, int at, int src_s, int str_s)
{
	int i, j;

	if (src == NULL || str_s + at > src_s)
		return -1;

	for (i = at, j=0; j < str_s; i++, j++)
	{
		src[i] = str[j];
	}

    return 0;
}

int string_length(char *str)
{
    if (str == NULL)
    {
        return -1;
    }

    int i = 0;
    while (str[i] != '\0')
    {
        i++;
    }

    return i;
}

char *int_to_string(int x)
{
    int i = 1;
    int j, tmp = x;

    while ((tmp/=10) != 0)
    {
        ++i;
    }

    char *str = (char *)malloc(sizeof(char)*(i+1));

    for (j = i - 1; j >= 0; j--)
    {
        str[j] = (char)(x % 10 + '0');
        x /= 10;
    }

	str[i] = '\0';

    return str;
}


int log_entry(struct entry *ent)
{
	if (ent == NULL)
	{
		return -1;
	}

	// MUST DECRYPT.
	k = "private.key";
	in = "enc_file_logging.log";
	out = "file_logging.log";
	
	decryption();



	// OPEN FILE.
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(LOG_FILE_NAME, "a");

	if (original_fopen_ret == NULL)
	{
		perror("error opening file\n");
	}



	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);


	// Construct string of entry
	char log_entry[1000];
	int index=0;
	char *header = "=============== ENTRY ===============\nuid: ";
	index += string_length(header);
	join_string_at(log_entry, header, 0, 1000, index);
	char *uid = int_to_string(ent->uid);
	int size = string_length(uid);
	join_string_at(log_entry, uid, index, 1000, size);
	index+=size;
	free(uid);

	char *log_d1 = "\naccess_type: ";
	size = string_length(log_d1);
	join_string_at(log_entry, log_d1, index, 1000, size);
	index += size;

    char access_type = (char)(ent->access_type + '0');
	join_string_at(log_entry, &access_type, index, 1000, 1);
	index += 1;

	char *log_d2 = "\naction_denied: ";
	size = string_length(log_d2);
	join_string_at(log_entry, log_d2, index, 1000, size);
	index += size;

    char action_denied = (char)(ent->action_denied + '0');
	join_string_at(log_entry, &action_denied, index, 1000, 1);
	index += 1;

	char *log_d3 = "\ndate: ";
	size = string_length(log_d3);
	join_string_at(log_entry, log_d3, index, 1000, size);
	index += size;

	size = string_length(ent->date);
	join_string_at(log_entry, ent->date, index, 1000, size);
	index += size;

	char *log_d4 = "\ntime: ";
	size = string_length(log_d4);
	join_string_at(log_entry, log_d4, index, 1000, size);
	index += size;

	size = string_length(ent->time);
	join_string_at(log_entry, ent->time, index, 1000, size);
	index += size;

	char *log_d5 = "\nfile: ";
	size = string_length(log_d5);
	join_string_at(log_entry, log_d5, index, 1000, size);
	index += size;
	
	size = string_length(ent->file);
	join_string_at(log_entry, ent->file, index, 1000, size);
	index += size;

	char *log_d6 = "\nfingerprint: ";
	size = string_length(log_d6);
	join_string_at(log_entry, log_d6, index, 1000, size);
	index += size;
	
	size = string_length(ent->fingerprint);
	join_string_at(log_entry, ent->fingerprint, index, 1000, size);
	index += size;

	char *footer = "\n=====================================\n";
    size = string_length(footer);
    join_string_at(log_entry, footer, index, 1000, size);
    index += size;

    log_entry[index] = '\0';


	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(log_entry, sizeof(char), index, original_fopen_ret);
	
	if (original_fwrite_ret != index)
	{
		perror("error writing");
	}


	fclose(original_fopen_ret);


	// MUST ENCRYPT
	k = "public.key";
	out = "enc_file_logging.log";
	in = "file_logging.log";
	encryption();


	return 1;
}


FILE *
fopen(const char *path, const char *mode) 
{

	key_generation();

	// Check if a file exists before opening it.
	int exists = file_exists(path);
	
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	// get a copy of the path to pass it as non const
	char cp_path[100];
	strcpy(cp_path, path);

	// save path reference
	strcpy(file_opened, path);


	// Create an entry
	struct entry *new_entry = (struct entry*)malloc(sizeof(struct entry));
	


	// UID
	new_entry->uid = getuid();
	// File path
	new_entry->file = (char *)malloc(sizeof(char)*string_length(cp_path));
	strcpy(new_entry->file, path);


	// Date Time
	time_t t = time(NULL);
	struct tm td = *localtime(&t);
	char time[20];
	char date[20];
	strftime(time, sizeof(time), "%X", &td);
	strftime(date, sizeof(date), "%x", &td);
	new_entry->date = (char *) malloc(sizeof(char) *string_length(date));
	new_entry->time = (char *) malloc(sizeof(char) *string_length(time));
	strcpy(new_entry->date, date);
	strcpy(new_entry->time, time);


	// Access type
	int access_value = access(path, F_OK);
	//printf("%d\n", access_value);
	if (!exists) // FILE DOES NOT EXIST
	{
		new_entry->access_type = 0;
	} 
	else if (check_if_empty_file(cp_path) && errno != ENOENT) // CAN ACCESS, EXISTS BUT ITS EMPTY
		new_entry->access_type = 3;
	else // CAN ACCESS, EXISTS, NOT EMPTY
		new_entry->access_type = 1;	// Else just open type.
	if (access_value == -1 && errno == EACCES) // CANNOT ACCESS
		new_entry->action_denied = 1;
	else
		new_entry->action_denied = 0; // CAN ACESS

	
	

	new_entry->fingerprint = file_fingerprint(cp_path);
	


	// write new entry.
	log_entry(new_entry);


	free(new_entry->time);
	free(new_entry->date);
	free(new_entry->file);
	free(new_entry->fingerprint);
	free(new_entry);


	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	// Check if a file exists.
	int exists = file_exists(file_opened);

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);


	// Create an entry
	struct entry *new_entry = (struct entry*)malloc(sizeof(struct entry));
	
	// UID
	new_entry->uid = getuid();
	// File path
	new_entry->file = (char *)malloc(sizeof(char)*string_length(file_opened));
	strcpy(new_entry->file, file_opened);

	// Date Time
	time_t t = time(NULL);
	struct tm td = *localtime(&t);
	char time[20];
	char date[20];
	strftime(time, sizeof(time), "%X", &td);
	strftime(date, sizeof(date), "%x", &td);
	new_entry->date = (char *) malloc(sizeof(char) *string_length(date));
	new_entry->time = (char *) malloc(sizeof(char) *string_length(time));
	strcpy(new_entry->date, date);
	strcpy(new_entry->time, time);
	
	// Access type
	int access_value = access(file_opened, F_OK);
	//printf("Write:%d\n", access_value);

	if (!exists) // FILE DOES NOT EXIST
		new_entry->access_type = 0;

	if (access_value == -1 && errno == EACCES) // CANNOT ACCESS
		new_entry->action_denied = 1;
	else
		new_entry->action_denied = 0; // CAN ACESS
	if (check_if_empty_file(file_opened)) // CAN ACCESS, EXISTS BUT ITS EMPTY
		new_entry->access_type = 3;
	else // CAN ACCESS, EXISTS, NOT EMPTY
		new_entry->access_type = 2;	// Else just write type.
	


	new_entry->fingerprint = file_fingerprint(file_opened);
	


	// write new entry.
	log_entry(new_entry);

	free(new_entry->file);
	free(new_entry->time);
	free(new_entry->date);
	free(new_entry->fingerprint);
	free(new_entry);



	return original_fwrite_ret;
}


void key_generation()
{
    // 2 Large primes
    mpz_t p;
    mpz_t q;
    mpz_init(p);
    mpz_init(q);

    // n = p * q
    mpz_init(n);

    
    // SET KEYS  AS DEFAULT PRIMES

    mpz_set_ui(p, PRIME1);
    mpz_set_ui(q, PRIME2);

    // Multiplication: n = p * q
    mpz_mul(n, p, q);

   
    // Calculate lambda euler func.
    mpz_t lambda;
    mpz_init(lambda);
    lambda_euler_function(lambda, p, q);

 
    // Choose an e. Prime and larger than lambda.
    mpz_init(d);   
    forge_d_key(d, lambda);
    
 
    // Calculate d : modular inverse of(e, lambda)
    mpz_init(e);
    mpz_invert(e, d, lambda);


    // public key: (n, d)
    // private key: (n, e)


    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(lambda);


    FILE *original_fopen_ret1;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret1 = (*original_fopen)("public.key", "w");

    FILE *original_fopen_ret2;

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret2 = (*original_fopen)("private.key", "w");

    
    if (original_fopen_ret1 == NULL|| original_fopen_ret2 == NULL)
    {
        printf("Error opening a file. Program will now terminate...\n");

        destruct();
    }
 

    // Write to file
    fprintf(original_fopen_ret1, "(");
    mpz_out_str(original_fopen_ret1, 10, n);
    fprintf(original_fopen_ret1,",");
    mpz_out_str(original_fopen_ret1, 10, e);
    fprintf(original_fopen_ret1,")");
    fflush(original_fopen_ret1);
    
    fprintf(original_fopen_ret2, "(");
    mpz_out_str(original_fopen_ret2, 10, n);
    fprintf(original_fopen_ret2,",");
    mpz_out_str(original_fopen_ret2, 10, d);
    fprintf(original_fopen_ret2,")");
    
    
    
    fflush(original_fopen_ret2);
    
    fclose(original_fopen_ret1);
    fclose(original_fopen_ret2);
    
}

void encryption()
{
    FILE *original_fopen_retK;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_retK = (*original_fopen)(k, "r");

    if (original_fopen_retK == NULL)
    {
        printf("Error opening file. Program will exit...\n");

        destruct();
    }


    // Fetch the keys.
    char buffer[MAX_BUFFER];
    char *n;
    char *e;
    char ch;
    int i = 0;
    int j = 0;
    int k = 0;


    while ((ch = fgetc(original_fopen_retK)) != EOF)
    {
        if (ch != EOF)
        {
            buffer[i++] = ch;

            if (ch == ',')
            {
                n = (char*)malloc(sizeof(char)*i);

                int c = 0;
                for (j = 0; j < i - 1; j++)
                {
                    if (buffer[j] != '(' && buffer[j] != ',')
                    {
                        n[c++] = buffer[j];
                    }
                }

            }
            else if (ch == ')')
            {
                e = (char*)malloc(sizeof(char)*(i-j));
                
                int b = 0;
                for (k = 0; k < i - j; k++)
                {
                    if (buffer[j + k] != ',' && buffer[j + k] != ')')
                    {
                        e[b++] = buffer[j + k];
                    }
                }

                break;
            }
        }
    }

    char *keys = (char*) malloc(sizeof(char)*i);
    j=0;
    for (j = 0; j < i; j++)
    {
        keys[j] = buffer[j];
    }

    fclose(original_fopen_retK);

    free(keys); 
    remove(buffer);


    // Fetch the plain_text from input.
    FILE *original_fopen_retI;

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_retI = (*original_fopen)(in, "r");

    if (original_fopen_retI == NULL)
    {
        printf("Error opening file. Program will exit...\n");

        destruct();
    }


    char plaintext[MAX_BUFFER];
    char c;
    i = 0;

    while ((c = fgetc(original_fopen_retI)) != EOF)
    {
        if (c != EOF)
        {
            plaintext[i++] = c;
        }
    }
    i--;


    int size = i;

    // print plaintext
    //printf("PLAINTEXT: %s", plaintext);
    
    fclose(original_fopen_retI);

    // create mpz_t numbers;
    mpz_t ekey;
    mpz_t nkey;

    mpz_init(ekey);
    mpz_init(nkey);

    mpz_set_str(ekey, e, 10);
    mpz_set_str(nkey, n, 10);

    size_t* cipher = (size_t*)malloc(sizeof(size_t)*size);
    // encrypt. Encrypt method responsible to write  the cipher.
    cipher = encrypt(cipher, plaintext, size, ekey, nkey);

      
    // print cipher
    //printf("CIPHER: ");
    //print_cipher(cipher, size);



    mpz_clear(nkey);
    mpz_clear(ekey);
    free(cipher);
    free(e);
    free(n);
    fflush(stdout);
 
}

size_t* encrypt(size_t* cipher, char *plaintext, int size, mpz_t puKey, mpz_t n)
{
    
    int i; 
    mpz_t ch;
    mpz_init(ch);
    mpz_t powm;
    mpz_init(powm);


 

    size_t buffer[8];

    FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(out, "wb");

    if (original_fopen_ret == NULL)
    {
        printf("Error opening file. Program will exit...\n");

        destruct();
    }

    for (i = 0; i < size; i ++)
    {
        mpz_set_ui(ch, plaintext[i]);
        mpz_powm(powm, ch, puKey, n);
        
        cipher[i] = (uint64_t)mpz_get_ui(powm);
        mpz_export(buffer, NULL, 1, 8, 0, 0, powm);

        fwrite(buffer, 8, 1, original_fopen_ret);

   

    }


    fclose(original_fopen_ret);
    mpz_clear(ch);
    mpz_clear(powm);

    return cipher;
}

void decryption()
{
    FILE *original_fopen_retk;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_retk = (*original_fopen)(k, "r");

    if (original_fopen_retk == NULL)
    {
        printf("Error opening file. Program will exit...\n");

        destruct();
    }


    // Fetch the keys.
    char buffer[MAX_BUFFER];
    char *n;
    char *d;
    char ch;
    int i = 0;
    int j = 0;
    int k = 0;


    while ((ch = fgetc(original_fopen_retk)) != EOF)
    {
        if (ch != EOF)
        {
            buffer[i++] = ch;

            if (ch == ',')
            {
                n = (char*)malloc(sizeof(char)*i);

                int c = 0;
                for (j = 0; j < i - 1; j++)
                {
                    if (buffer[j] != '(' && buffer[j] != ',')
                    {
                        n[c++] = buffer[j];
                    }
                }

            }
            else if (ch == ')')
            {
                d = (char*)malloc(sizeof(char)*(i-j));
                
                int b = 0;
                for (k = 0; k < i - j; k++)
                {
                    if (buffer[j + k] != ',' && buffer[j + k] != ')')
                    {
                        d[b++] = buffer[j + k];
                    }
                }

                break;
            }
        }
    }

    char *keys = (char*) malloc(sizeof(char)*i);
    j=0;
    for (j = 0; j < i; j++)
    {
        keys[j] = buffer[j];
    }
    // print keys
    //printf("keys: %s\nn: %s\ne: %s\n", keys, n, d);
    fclose(original_fopen_retk);

    free(keys); 
    remove(buffer);




    // create mpz_t numbers from keys;
    mpz_t dkey;
    mpz_t nkey;
    mpz_init(dkey);
    mpz_init(nkey);

    mpz_set_str(dkey, d, 10);
    mpz_set_str(nkey, n, 10);

    // encrypt.
    char* plaintext = decrypt(dkey, nkey);



    // Write deciphered to output.	
	FILE *original_fopen_retO;

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_retO = (*original_fopen)(out, "w");

    if (original_fopen_retO == NULL)
    {
        printf("Error opening file. Program will exit...\n");

        destruct();
    }
    
    // print cipher
    //printf("DECIPHER:%s\n", plaintext);


    fprintf(original_fopen_retO, "%s", plaintext);


    // Clean up
    mpz_clear(nkey);
    mpz_clear(dkey);
    free(plaintext);
    free(d);
    free(n);
    fflush(stdout);
    fclose(original_fopen_retO);
}

char* decrypt(mpz_t prKey, mpz_t n)
{

    int i;

    mpz_t ch;
    mpz_init(ch);
    mpz_t powm;
    mpz_init(powm);



    FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(in, "rb");

    if (original_fopen_ret == NULL)
    {
        printf("Error opening file. Program will exit...\n");

        destruct();
    }

    fseek(original_fopen_ret, 0, SEEK_END);
    unsigned long int size = ftell(original_fopen_ret);
    fseek(original_fopen_ret, 0, SEEK_SET);


    size_t buffer[8];
    // Caller must free.
    char* plaintext = (char*)malloc(sizeof(char) *size/8);

    for (i = 0; i < size/8; i ++)
    {
        fread(buffer, 8, 1, original_fopen_ret);
        mpz_import(ch, 1, 1, 8, 0, 0, buffer);

        mpz_powm(powm, ch, prKey, n);
        plaintext[i] = mpz_get_ui(powm);
    }
    plaintext[i] = '\0';


    fclose(original_fopen_ret);
    mpz_clear(ch);
    mpz_clear(powm);

    

    return plaintext;
}
void destruct()
{
    mpz_clear(n);
    mpz_clear(d);
    mpz_clear(e);

    exit(1);
}



