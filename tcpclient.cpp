/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   main.cpp
 * Author: alsabawi
 *
 * Created on February 2, 2017, 11:06 AM
 */

#include <cstdlib>


/*
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
extern "C" {
int h_errno;
}
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <chrono>
#include <fstream>

#ifdef __linux__
#include <linux/sockios.h>
#endif

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
// Boost C++ Lib
#include<boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include<string>
#include <bits/basic_string.h>

// Local headers
#include "json.hpp"
#include "sqlite3.h"
#include <sys/ioctl.h>
#include <bits/stl_vector.h>

// namespaces
using namespace std;
using namespace boost;
using json = nlohmann::json;

// Constants
#define NATIVE_PROTO    0
#define HTTP_PROTO      1
#define SSH_PROTO       2

#define MY_DEFAULT_NAME "ABBAS"
#define KEY_SIZE 32
#define BLOCK_SIZE 16
#define RANDOMKEY_SIZE 32
#define MEMSIZE 32768
#define CLIENT_BUFFER_SIZE MEMSIZE
#define DEFAULT_KETY_DIR "./ssh"
#define DOWNLOAD_DIR "./downloads"
#define PROMPT_TEXT "CMD/Text>"
#define QUIT_CLIENT_CHARS "!q"
#define NAME_SIZE 100

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

#ifdef __CYGWIN__ 
#define gethostbyname_r gethostbyname
#endif

// Types and structs

typedef struct command_data {
    char parm_name[NAME_SIZE];
    char parm_value[NAME_SIZE];
    command_data *next;
} cmd_data, *pcmd_data;

typedef struct commands {
    char cmd[NAME_SIZE];
    pcmd_data pdata;
    commands *next;
} cmd, *pcmd;

typedef struct comm_data {
    char alias[255];
    char hostname[255];
    int sockfd;
    int portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    bool encrypt;
    int status;
    int reconnect_count;
} tcpcomm, *ptcpcomm;

typedef struct errorrectype {
    int errorno;
    char message[255];
} errorrec, *perrorrec;

typedef struct conndata {
    RSA * peer_public_rsa;

    unsigned char * peer_public_key_string;
    long peer_public_key_len;
    unsigned char *session_key;
    int session_key_len;
    unsigned char * session_rsa;
    unsigned char * session_iv;
    EVP_PKEY *EVP_key;

    tcpcomm comm;
} connection_data, *pconnection_data;

typedef struct commchain {
    pconnection_data pthis;
    commchain * prev;
    commchain * next;
} comm_chain, *pcomm_chain;

typedef struct {
    pcomm_chain pChainStart;
    int count;
} commhook;

typedef struct proc_golobals {
    RSA * my_private_rsa;
    char myname[NAME_SIZE];
    unsigned char * mypublic_key_string;
    long mypublic_key_len;
    sqlite3 *db;
    commhook CommHook = {NULL, 0};
    errorrec last_error;
} proc_data, *pproc_data;


// Globals
pcmd pCommandChain = NULL;
pproc_data pLocalProc = NULL;
int padding1 = RSA_PKCS1_PADDING;
int padding0 = RSA_NO_PADDING;
char *publicKey = NULL;


//static char httpRequest[] = "GET / HTTP/1.1 Host: localhost:3490 User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate Connection: keep-alive Upgrade-Insecure-Requests: 1";

// prototypes
int run_client(int, char **, sqlite3 *);
bool pem_readkeyfile(char *, bool, RSA **);
int add_key_to_db(unsigned char *, unsigned char *);

int sym_decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
int sym_encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
int sym_encrypt2(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *);
int noenc_read(pcomm_chain, char *, int, int);
int noenc_write(pcomm_chain, char *, int, int);
void set_last_error(int, const char *);
int disconnect_from_peer(pcomm_chain *);

inline bool isInteger(const std::string & s)
{
    if (s.empty () || ((!isdigit (s[0])) && (s[0] != '-') && (s[0] != '+'))) return false;

    char * p;
    strtol (s.c_str (), &p, 10);

    return (*p == 0);
}

int print_help()
{
    cout << "Local Commands:\n";
    cout << "\t !q : Exit client \n";
    cout << "\t connect <hostname> <port number> [as alias] : Connect to remote host\n";
    cout << "\t diconnect <alias> : Disconnect from remote host\n";
    cout << "\t show connections : List active connections\n";
    cout << "\t show myname : Show client current name \n";
    cout << "\t set myname <client name> : Set client current name\n";
    cout << endl;

    cout << "Remote Commands: \n";
    cout << "\t get file <remote filename> : Request a file from remote host\n";
    cout << "\t run <remote sscript> : Execute remote script at the host\n";
}

inline bool filestat(const std::string& name, struct stat *pstatbuf, char * _filemode)
{
    char *filemode = "";
    bool exists = ((pstatbuf = stat (name.c_str (), pstatbuf)) == 0);
    if (!exists)
	return false;

    //    filemode[0] = ( (pstatbuf->st_mode & S_IRUSR) ? "r" : "-");
    //    filemode[1] =( (pstatbuf->st_mode & S_IWUSR) ? "w" : "-");
    //    filemode[2] =( (pstatbuf->st_mode & S_IXUSR) ? "x" : "-");
    //    filemode[3] =( (pstatbuf->st_mode & S_IRGRP) ? "r" : "-");
    //    filemode[4] =( (pstatbuf->st_mode & S_IWGRP) ? "w" : "-");
    //    filemode[5] =( (pstatbuf->st_mode & S_IXGRP) ? "x" : "-");
    //    filemode[6] =( (pstatbuf->st_mode & S_IROTH) ? "r" : "-");
    //    filemode[7] =( (pstatbuf->st_mode & S_IWOTH) ? "w" : "-");
    //    filemode[8] =( (pstatbuf->st_mode & S_IXOTH) ? "x" : "-");
    strcpy (_filemode, filemode);

    return true;
}

void *mymalloc(size_t s)
{
    try
    {
	void *m = malloc (s);
	if (m == NULL)
	{
	    cout << "Unable to allocate memory \n";
	    exit (-1);
	}
	else
	{
	    return m;
	}
    }

    catch (const std::runtime_error& re)
    {
	// speciffic handling for runtime_error
	std::cerr << "Runtime error: " << re.what () << std::endl;
    }
    catch (const std::exception& ex)
    {
	// speciffic handling for all exceptions extending std::exception, except
	// std::runtime_error which is handled explicitly
	std::cerr << "Error occurred: " << ex.what () << std::endl;
    }
    catch (...)
    {
	// catch any other errors (that we have no information about)
	std::cerr << "Unknown failure occurred. Possible memory corruption" << std::endl;
    }
}

pcomm_chain add_comm_link()
{
    pcomm_chain pCommChain = pLocalProc->CommHook.pChainStart;
    if (pLocalProc->CommHook.pChainStart == NULL)
    {
	pCommChain = (pcomm_chain) mymalloc (sizeof (comm_chain));
	pCommChain->pthis = (pconnection_data) mymalloc (sizeof (connection_data));
	pCommChain->pthis->EVP_key = NULL;
	pCommChain->pthis->peer_public_key_len = 0;
	pCommChain->pthis->peer_public_key_string = NULL;
	pCommChain->pthis->peer_public_rsa = NULL;
	pCommChain->pthis->session_iv = NULL;
	pCommChain->pthis->session_key = NULL;
	pCommChain->pthis->session_key_len = 0;
	pCommChain->pthis->session_rsa = NULL;
	pCommChain->prev = NULL;
	pCommChain->next = NULL;
	pLocalProc->CommHook.count = 1;
	pLocalProc->CommHook.pChainStart = pCommChain;
	return pCommChain;
    }
    else
    {
	pcomm_chain pTest = pCommChain;
	while (pTest->next != NULL)
	{
	    pTest = pTest->next;
	}
	pTest->next = (pcomm_chain) mymalloc (sizeof (comm_chain));
	pTest->next->pthis = (pconnection_data) mymalloc (sizeof (connection_data));
	pTest->next->pthis->EVP_key = NULL;
	pTest->next->pthis->peer_public_key_len = 0;
	pTest->next->pthis->peer_public_key_string = NULL;
	pTest->next->pthis->peer_public_rsa = NULL;
	pTest->next->pthis->session_iv = NULL;
	pTest->next->pthis->session_key = NULL;
	pTest->next->pthis->session_key_len = 0;
	pTest->next->pthis->session_rsa = NULL;
	pTest->next->next = NULL;
	pTest->next->prev = pTest;
	pLocalProc->CommHook.count++;
	return pTest->next;
    }
}

bool delete_comm_link(pcomm_chain *pthisChain)
{
    if (*pthisChain != NULL)
    {
	if ((*pthisChain)->prev != NULL)
	{
	    (*pthisChain)->prev->next = (*pthisChain)->next;
	}
	else
	{
	    pLocalProc->CommHook.pChainStart = (*pthisChain)->next;
	}

	if ((*pthisChain)->next != NULL)
	    (*pthisChain)->next->prev = (*pthisChain)->prev;

	if ((*pthisChain)->pthis != NULL)
	{
	    //( *pthisChain )->pthis->peer_public_rsa;

	    if ((*pthisChain)->pthis->peer_public_key_string != NULL
	    && (*pthisChain)->pthis->peer_public_key_len > 0)
	    {
		free ((*pthisChain)->pthis->peer_public_key_string);
		(*pthisChain)->pthis->peer_public_key_string = NULL;
		(*pthisChain)->pthis->peer_public_key_len = 0;
	    }
	    if ((*pthisChain)->pthis->EVP_key != NULL)
	    {
		EVP_PKEY_free ((*pthisChain)->pthis->EVP_key);
		(*pthisChain)->pthis->EVP_key = NULL;
	    }
	    if ((*pthisChain)->pthis->session_rsa != NULL)
	    {
		free ((*pthisChain)->pthis->session_rsa);
		(*pthisChain)->pthis->session_rsa = NULL;
	    }
	    if ((*pthisChain)->pthis->session_iv != NULL)
	    {
		free ((*pthisChain)->pthis->session_iv);
		(*pthisChain)->pthis->session_iv = NULL;
	    }

	    (*pthisChain)->pthis->session_key = NULL;
	    (*pthisChain)->pthis->session_key_len = 0;

	    free ((*pthisChain)->pthis);
	    (*pthisChain)->pthis = NULL;

	    free (*pthisChain);
	    *pthisChain = NULL;
	}
	else
	{
	    free (*pthisChain);
	    *pthisChain = NULL;
	}
	pLocalProc->CommHook.count--;
	return true;
    }
    else
    {
	return false;
    }
}

bool delete_all_comm_links()
{
    bool rc = true;
    // delete them all
    pcomm_chain pCommChain = pLocalProc->CommHook.pChainStart;
    for (int i = 0; i < 10 && rc; i++)
    {
	rc = delete_comm_link (&pCommChain);
	pCommChain = pLocalProc->CommHook.pChainStart;
    }
    return rc;
}

pcmd new_command()
{
    pcmd p = (pcmd) malloc (sizeof (cmd));
    memset (p->cmd, 0, sizeof (p->cmd));
    p->pdata = NULL;
    p->next = NULL;
    return p;
}

void force_no_encryption()
{
    // NOTE:
    // -- For NO encryption at all, NULL session_iv, session_rsa, and peer_rsa    
    // -- For Asym RSA encryption ONLY, NULL session_iv and session_rsa while comment out
    //    peer_rsa = NULL
    // -- For FULL encryption with noth Asym and Sym, comment out ALL Nulling lines below

    //pLocalProc->session_iv = NULL;
    //pLocalProc->session_rsa = NULL; 

    //pLocalProc->peer_rsa = NULL; 
}

void depleteSendBuffer(int fd)
{
#ifdef __linux__
    int i = 0, attempts = 5;
    int lastOutstanding = -1;
    for (i = 0; i < attempts; i++)
    {
	int outstanding = 0;
	ioctl (fd, SIOCOUTQ, &outstanding);
	//	if (outstanding != lastOutstanding)
	//	   cout << "Attempting to send Outstanding" << outstanding << " bytes \n";
	lastOutstanding = outstanding;
	if (!outstanding)
	    break;
	usleep (250);
    }
#endif
}

void hexdump(unsigned char *buffer, int buffer_len)
{
    unsigned char *xbuf = (unsigned char *) malloc ((buffer_len * 4 * sizeof (unsigned char)) + 1);

    char t[2];
    for (int j = 0; j < buffer_len; j++)
    {
	sprintf (t, "%02x", (unsigned int) (buffer[j]));
	strcpy (&xbuf[2 * j], t);
	if (j % 28 == 0)
	{
	    sprintf (&xbuf[(2 * j) + 2], " \n");
	}
    }
    printf (xbuf);
    printf ("\n");
    for (int i = 0; i < buffer_len; i++)
    {
	putchar (buffer[i]);
    }
    printf ("\n");
    free (xbuf);
}

pcmd_data new_command_data()
{
    pcmd_data p = (pcmd_data) malloc (sizeof (cmd_data));
    memset (p->parm_name, 0, sizeof (p->parm_name));
    memset (p->parm_value, 0, sizeof (p->parm_value));
    p->next = NULL;
    return p;
}

long random_at_most(unsigned int min, unsigned int max)
{
    int r;
    const unsigned int range = 1 + max - min;
    const unsigned int buckets = RAND_MAX / range;
    const unsigned int limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do
    {
	r = rand ();
    }
    while (r >= limit);

    return min + (r / buckets);

}

int generate_ascii_string(char * str, int max_len)
{
    int size = random_at_most (1, max_len);
    char buf[max_len];

    for (int i = 0; i < size; i++)
    {
	buf[i] = '0' + random_at_most (1, 255);

    }
    buf[size] = '\0';
    strcpy (str, buf);
    return size;
}

void fatal_error(const char *msg)
{
    perror (msg);
    exit (0);
}

void printLastError(char *msg)
{
    char * err = (char *) malloc (130);

    ERR_load_crypto_strings ();
    ERR_error_string (ERR_get_error (), err);
    printf ("%s ERROR: %s\n", msg, err);
    printf ("Encryption failed! \n");
    free (err);
}

int private_decrypt(RSA *rsa, unsigned char *enc_data, int data_len, unsigned char *decrypted, pcomm_chain pConnection)
{
    int result = -1;
    //cout << enc_data << endl;
    if (pConnection->pthis->session_key == NULL || pConnection->pthis->session_iv == NULL)
    {
	result = RSA_private_decrypt (data_len, enc_data, decrypted, rsa, padding1);
    }
    else
    {
	result = sym_decrypt (enc_data, data_len, pConnection->pthis->session_rsa,
		pConnection->pthis->session_iv, decrypted);
    }

    return result;
}

int private_encrypt(RSA *rsa, unsigned char * data, int data_len, unsigned char *encrypted, pcomm_chain pConnection)
{
    int result = -1;
    if (pConnection->pthis->session_key == NULL || pConnection->pthis->session_iv == NULL)
    {
	result = RSA_private_encrypt (data_len, data, encrypted, rsa, padding1);
    }
    else
    {
	result = sym_encrypt (data, data_len, pConnection->pthis->session_rsa,
		pConnection->pthis->session_iv, encrypted);
    }

    return result;
}

int public_encrypt(RSA *rsa, unsigned char * data, int data_len, unsigned char *encrypted, pcomm_chain pConnection)
{
    int result = -1;
    if (pConnection->pthis->session_key == NULL || pConnection->pthis->session_iv == NULL)
    {
	result = RSA_public_encrypt (data_len, data, encrypted, rsa, padding1);
    }
    else
    {
	result = sym_encrypt (data, data_len, pConnection->pthis->session_rsa,
		pConnection->pthis->session_iv, encrypted);
    }
    return result;
}

int public_decrypt(RSA *rsa, unsigned char * enc_data, int data_len, unsigned char *decrypted, pcomm_chain pConnection)
{
    int result = -1;
    if (pConnection->pthis->session_key == NULL || pConnection->pthis->session_iv == NULL)
    {
	result = RSA_public_decrypt (data_len, enc_data, decrypted, rsa, padding1);
    }
    else
    {
	result = sym_decrypt (enc_data, data_len, pConnection->pthis->session_rsa,
		pConnection->pthis->session_iv, decrypted);
    }
    return result;
}

int sym_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new ()))
	printLastError ("sym_encrypt()>EVP_CIPHER_CTX_new()");

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv))
    {
	printLastError ("sym_encrypt()>EVP_EncryptInit_ex()");
	return -1;
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate (ctx, ciphertext, &len, plaintext, plaintext_len))
    {
	printLastError ("sym_encrypt()>EVP_EncryptUpdate()");
	return -1;
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex (ctx, ciphertext + len, &len))
    {
	printLastError ("sym_encrypt()>EVP_EncryptFinal_ex()");
	return -1;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free (ctx);

    //cout << ">> OUT OF sym_encrypt()\n";
    return ciphertext_len;
}

int sym_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    //EVP_CIPHER_CTX_init(&ctx);
    if (!(ctx = EVP_CIPHER_CTX_new ()))
    {
	printLastError ("sym_decrypt()>EVP_CIPHER_CTX_new()");
	return -1;
    }
    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv))
    {
	printLastError ("sym_decrypt()>EVP_DecryptInit_ex()");
	return -1;
    }

    //EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate (ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
	printLastError ("sym_decrypt()>EVP_DecryptUpdate()");
	return -1;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex (ctx, plaintext + len, &len))
    {
	printLastError ("sym_decrypt()>EVP_DecryptUpdate()");
	return -1;
    }
    plaintext_len += len;

    //    plaintext[plaintext_len] = '\0';

    /* Clean up */
    EVP_CIPHER_CTX_free (ctx);

    //printf (">>>decrypted to Plan text : %s\n", plaintext);

    //cout << ">> OUT OF sym_decrypt()\n";
    return plaintext_len;
}

//void init_openssl(void)
//{
//    if (SSL_library_init())
//    {
//	SSL_load_error_strings();
//	OpenSSL_add_all_algorithms();
//	RAND_load_file("/dev/urandom", 1024);
//    }
//    else
//	exit(EXIT_FAILURE);
//}

void cleanup_openssl(void)
{
    CRYPTO_cleanup_all_ex_data ();
    ERR_free_strings ();
    ERR_remove_thread_state (0);
    EVP_cleanup ();
}

void handle_openssl_error(void)
{
    ERR_print_errors_fp (stderr);
}

bool pem_readkeyfile(char *filename, bool isPrivateKey, RSA **rsakey, EVP_PKEY **key)
{
    FILE* pFile = NULL;
    const EVP_CIPHER* pCipher = NULL;
    //EVP_PKEY* key;
    //init_openssl();
    *rsakey = NULL;
    /* Read the keys */
    if (isPrivateKey)
    {
	if ((pFile = fopen (filename, "rt")) &&
	(*key = PEM_read_PrivateKey (pFile, NULL, NULL, NULL)))
	{
	    fprintf (stderr, "Private key read.\n");
	}
	else
	{
	    fprintf (stderr, "Cannot read %s.\n", filename);
	    handle_openssl_error ();
	    return false;
	}
	if (pFile)
	{
	    fclose (pFile);
	    pFile = NULL;
	}
    }
    else
    {
	if ((pFile = fopen (filename, "rt")) &&
	(*key = PEM_read_PUBKEY (pFile, NULL, NULL, NULL)))
	{
	    fprintf (stderr, "Public key read.\n");
	}
	else
	{
	    fprintf (stderr, "Cannot read %s.\n", filename);
	    handle_openssl_error ();
	    return false;
	}
    }

    *rsakey = EVP_PKEY_get1_RSA (*key);

    if (isPrivateKey)
    {
	if (RSA_check_key (*rsakey))
	{
	    printf ("RSA key is valid.\n");
	}
	else
	{
	    printf ("Error validating RSA key.\n");
	    handle_openssl_error ();
	    return false;
	}
    }
    return true;
    cleanup_openssl ();
}

char *read_keyfile(char *file_name)
{
    char *source = NULL;
    FILE *fp = fopen (file_name, "r");
    if (fp != NULL)
    {
	/* Go to the end of the file. */
	if (fseek (fp, 0L, SEEK_END) == 0)
	{
	    /* Get the size of the file. */
	    long bufsize = ftell (fp);
	    if (bufsize == -1)
	    {
		/* Error */
	    }

	    /* Allocate our buffer to that size. */
	    source = (char *) malloc (sizeof (char) * (bufsize + 1));

	    /* Go back to the start of the file. */
	    if (fseek (fp, 0L, SEEK_SET) != 0)
	    {
		/* Error */
	    }

	    /* Read the entire file into memory. */
	    size_t newLen = fread (source, sizeof (char), bufsize, fp);
	    if (ferror (fp) != 0)
	    {
		fputs ("Error reading file", stderr);
	    }
	    else
	    {
		source[newLen++] = '\0'; /* Just to be safe. */
	    }
	}
	fclose (fp);
    }
    return source;
}

void handleErrors(void)
{
    fflush (stdout);

    printf ("\n***ERROR***\n");
    ERR_print_errors_fp (stderr);
    printf ("\n");
    exit (-1);
}

int set_session_key(unsigned char *tempkey, int tempkey_len, pcomm_chain pConnection)
{
    // Load the necessary cipher
    EVP_add_cipher (EVP_aes_256_cbc ());
    const EVP_CIPHER *cipher = EVP_get_cipherbyname ("aes-256-cbc");

    /* Initialise the library */
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();
    //    OPENSSL_config(NULL);

    const EVP_MD *dgst = NULL;
    const unsigned char *salt = NULL;

    OpenSSL_add_all_digests ();
    dgst = EVP_get_digestbyname ("md5");
    if (!dgst)
    {
	fprintf (stderr, "EVP_get_digestbyname() error: no such digest\n");
	return 1;
    }

    if (!EVP_BytesToKey (cipher, dgst, salt,
	(unsigned char *) tempkey,
	tempkey_len, 1, pConnection->pthis->session_rsa, pConnection->pthis->session_iv))
    {
	fprintf (stderr, "EVP_BytesToKey failed\n");
	return 1;
    }

    cout << "session keys set to server generated values \n";
    return 0;
}

int make_session_keys(unsigned char *retkey,
	unsigned char *retiv, unsigned char * genrated_key, int *genkey_len)
{
    // Load the necessary cipher
    EVP_add_cipher (EVP_aes_256_cbc ());
    const EVP_CIPHER *cipher = EVP_get_cipherbyname ("aes-256-cbc");

    /* Initialise the library */
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();
    //    OPENSSL_config(NULL);

    const EVP_MD *dgst = NULL;
    const unsigned char *salt = NULL;

    OpenSSL_add_all_digests ();
    dgst = EVP_get_digestbyname ("md5");
    if (!dgst)
    {
	fprintf (stderr, "EVP_get_digestbyname() error: no such digest\n");
	return 1;
    }

    // generate rundom number
    memset (genrated_key, 0, RANDOMKEY_SIZE);
    RAND_bytes (genrated_key, RANDOMKEY_SIZE);
    *genkey_len = RANDOMKEY_SIZE;

    if (!EVP_BytesToKey (cipher, dgst, salt,
	(unsigned char *) genrated_key,
	*genkey_len, 1, retkey, retiv))
    {
	fprintf (stderr, "EVP_BytesToKey failed\n");
	return 1;
    }

    return 0;
}

int retrieve_random_keys(const EVP_CIPHER *cipher, unsigned char *retkey, unsigned char *retiv, unsigned char *genrated_key, int rankey_len)
{

    const EVP_MD *dgst = NULL;
    const unsigned char *salt = NULL;

    OpenSSL_add_all_digests ();
    dgst = EVP_get_digestbyname ("md5");
    if (!dgst)
    {
	fprintf (stderr, "no such digest\n");
	return 1;
    }

    if (!EVP_BytesToKey (cipher, dgst, salt,
	(unsigned char *) genrated_key,
	rankey_len, 1, retkey, retiv))
    {
	fprintf (stderr, "EVP_BytesToKey failed\n");
	return 1;
    }

    return 0;
}

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, pcomm_chain pConnection)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char *encrypted_key;
    int encrypted_key_len;
    EVP_PKEY *pkey = EVP_PKEY_new ();
    unsigned char *iv;

    int ciphertext_len;

    int len;

    if (!EVP_PKEY_assign_RSA (pkey, pConnection->pthis->peer_public_rsa))
	handleErrors ();

    encrypted_key = (unsigned char *) malloc (EVP_PKEY_size (pkey));
    iv = malloc (EVP_MAX_IV_LENGTH);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new ())) handleErrors ();

    /* Initialise the envelope seal operation. This operation generates
     * a key for the provided cipher, and then encrypts that key a number
     * of times (one for each public key provided in the pub_key array). In
     * this example the array size is just one. This operation also
     * generates an IV and places it in iv. */
    if (1 != EVP_SealInit (ctx, EVP_aes_256_cbc (), &encrypted_key,
	&encrypted_key_len, iv, &pkey, 1))
	handleErrors ();

    //int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    //                 unsigned char **ek, int *ekl, unsigned char *iv,
    //                 EVP_PKEY **pubk, int npubk);
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_SealUpdate can be called multiple times if necessary
     */
    if (1 != EVP_SealUpdate (ctx, ciphertext, &len, plaintext, plaintext_len))
	handleErrors ();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_SealFinal (ctx, ciphertext + len, &len)) handleErrors ();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free (ctx);

    return ciphertext_len;
}

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, pcomm_chain pConnection)
{
    EVP_CIPHER_CTX *ctx;

    unsigned char *encrypted_key;
    int encrypted_key_len = EVP_PKEY_size (priv_key);
    ;
    unsigned char *iv;

    int len;

    int plaintext_len;

    encrypted_key = malloc (EVP_PKEY_size (priv_key));
    iv = malloc (EVP_MAX_IV_LENGTH);

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new ())) handleErrors ();

    /* Initialise the decryption operation. The asymmetric private key is
     * provided and priv_key, whilst the encrypted session key is held in
     * encrypted_key */
    if (1 != EVP_OpenInit (ctx, EVP_aes_256_cbc (), encrypted_key,
	&encrypted_key_len, iv, priv_key))
	handleErrors ();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_OpenUpdate can be called multiple times if necessary
     */
    if (1 != EVP_OpenUpdate (ctx, plaintext, &len, ciphertext, ciphertext_len))
	handleErrors ();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_OpenFinal (ctx, plaintext + len, &len)) handleErrors ();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free (ctx);

    return plaintext_len;
}

int enc_write(RSA *rsa, pcomm_chain pConnection, char *buffer, int buffer_length, int flag)
{
    int n = 0;
    char *p = buffer;
    int remaining = buffer_length;
    const char *ender = "end";

    unsigned char *send_buff = (unsigned char *) malloc (MEMSIZE * sizeof (unsigned char));
    unsigned char *encrypted = (unsigned char *) malloc (MEMSIZE * sizeof (unsigned char));

    while (remaining > 0 && n != -1)
    {
	int cp_len = remaining >= MEMSIZE ? MEMSIZE : remaining;
	strncpy (send_buff, &buffer[buffer_length - remaining], cp_len);
	remaining = remaining - cp_len;

	//printf("sending = %d\n", cp_len);
	int encrypted_length = public_encrypt (rsa, (unsigned char *) send_buff, cp_len, (unsigned char*) encrypted, pConnection);

	//int encrypted_length = envelope_seal(&pLocalProc->EVP_key, (unsigned char *)send_buff, cp_len, (unsigned char *)&encrypted);

	if (encrypted_length == -1)
	{
	    printLastError ((char *) "Public Encrypt failed ");
	    exit (0);
	}

	//cout << "sending enc " << buffer << endl;
	n = noenc_write (pConnection, encrypted, encrypted_length, flag);
    }

    if (n != -1)
	n = noenc_write (pConnection, ender, 3, 0);
    //printf("Sent %d bytes + 1\n", buffer_length);
    free (send_buff);
    free (encrypted);
    return n;
}

int enc_read(RSA *rsa, pcomm_chain pConnection, unsigned char *buffer, int buffer_size, int flag)
{
    bool quit = false;
    int rcv_parts = 0;
    //    unsigned char encrypted[MEMSIZE];
    //    unsigned char encrypted_clean[MEMSIZE];

    unsigned char *encrypted = (unsigned char *) malloc (MEMSIZE * sizeof (unsigned char));
    unsigned char *encrypted_clean = (unsigned char *) malloc (MEMSIZE * sizeof (unsigned char));

    int rc = 0;
    int received = 0;
    const char *ender = "end";
    while (!quit && (rc = noenc_read (pConnection, encrypted, MEMSIZE, flag)) >= 0)
    {
	char *buf = &encrypted[0];
	if ((strncmp (buf, ender, 3) == 0))
	{
	    break;
	}
	if ((strncmp (ender, &encrypted[rc - 3], 3) == 0))
	{
	    rc = rc - 3;
	    memcpy (encrypted_clean, encrypted, rc);
	    quit = true;
	}
	else
	{
	    memcpy (encrypted_clean, encrypted, rc);
	}
	rcv_parts++;

	int decrypted_length = private_decrypt (rsa, (unsigned char *) encrypted_clean, rc, (unsigned char *) buffer + received, pConnection);

	if (decrypted_length == -1)
	{
	    printLastError ((char*) "Error: Private Decrypt failed. Unable to decrypt message. ");
	    return -1;
	}
	received += decrypted_length;
    }
    buffer[received] = '\0';
    free (encrypted);
    free (encrypted_clean);
    return received;
}

int noenc_read(pcomm_chain pConnection, char *buffer, int buffer_size, int flag)
{

    int rc = 0;
    int received = 0;
    uint32_t l;
    struct timeval t;
    t.tv_sec = 2;
    t.tv_usec = 0;

    rc = recv (pConnection->pthis->comm.sockfd, &l, 4, 0);
    unsigned long ul = ntohl (l);

    do
    {
	rc = recv (pConnection->pthis->comm.sockfd, &buffer[received], ul - received, 0);
	if (rc == 0)
	    return -1;

	received += rc;
    }
    while (received < ul);
    return received;
}

int noenc_write(pcomm_chain pConnection, char * buffer, int buffer_len, int flag)
{
    int sent = 0;
    try
    {
	uint32_t l = htonl (buffer_len);

	sent = send (pConnection->pthis->comm.sockfd, &l, 4, 0);
	if (sent == -1)
	{
	    set_last_error (sent, "Lost connection with peer");
	    disconnect_from_peer (&pConnection);
	    return sent;
	}

	sent = send (pConnection->pthis->comm.sockfd, buffer, buffer_len, flag);
	if (sent == -1)
	{
	    set_last_error (sent, "Lost connection with peer");
	    disconnect_from_peer (&pConnection);
	    return sent;
	}
    }
    catch (std::exception& e)
    {
	perror ("Send");
	set_last_error (-1, e.what ());
	disconnect_from_peer (&pConnection);
	return -1;
    }
    return sent;
}

int WRITE(RSA *rsa, pcomm_chain pConnection, char * buffer, int buffer_len)
{
    int sent = 0;

    rsa ? sent = enc_write (rsa, pConnection, buffer, buffer_len, 0) : sent = noenc_write (pConnection, buffer, buffer_len, 0);

    return sent;

}

int READ(RSA *rsa, pcomm_chain pConnection, unsigned char *buffer, int buffer_size)
{
    int received = 0;

    rsa ? received = enc_read (rsa, pConnection, buffer, buffer_size, 0) : received = noenc_read (pConnection, buffer, buffer_size, 0);
    if (received == -1)
    {
	set_last_error (received, "Lost connection with peer");
	disconnect_from_peer (&pConnection);
    }
    return received;
}

int identify_protocol(std::string sbuf)
{
    int protocol = 0;
    // ******************************************************
    // Identify protocol
    if (sbuf.compare (0, 14, "GET / HTTP/1.1") == 0)
    {
	protocol = HTTP_PROTO; // HTTP protocol
    }
    else if (sbuf.compare (0, 3, "SSH") == 0)
    {
	protocol = SSH_PROTO; // SSH
    }
    else
    {
	protocol = NATIVE_PROTO;
    }
    return protocol;
}

void freeCommandData(pcmd_data d)
{
    if (d == NULL)
    {
	return;
    }
    else if (d->next == NULL)
    {
	free (d);
	d = NULL;
	return;
    }
    else
    {
	freeCommandData (d->next);
	free (d);
	d = NULL;
	return;
    }
}

void freeCommandChain(pcmd c)
{
    if (c == NULL)
    {
	return;
    }
    if (c->next == NULL)
    {
	freeCommandData (c->pdata);
	free (c);
	c = NULL;
	return;
    }
    else
    {
	freeCommandChain (c->next);
	freeCommandData (c->pdata);
	free (c);
	c = NULL;
	return;
    }
}

void dump_data(pcmd_data d)
{
    while (d)
    {
	d = d->next;
    }
}

void dump_command(pcmd c)
{
    while (c)
    {
	dump_data (c->pdata);
	c = c->next;
    }
}

int parse_remote_commands(json a, int inc, pcmd prev_cmd)
{
    char cinc[10];
    // cout << a << endl;

    try
    {
	sprintf (cinc, "%d\0", inc);
	if (a.find (cinc) == a.end ())
	{
	    return 0;
	}
	else
	{
	    string c;
	    if (!a.at (cinc).is_object ())
	    {
		return -1;
	    }
	    if (a.at (cinc).find ("response") == a.at (cinc).end ())
	    {
		return -1;
	    }

	    c.assign (a.at (cinc).find ("response").value ());

	    pcmd pc = new_command ();
	    if (prev_cmd) prev_cmd->next = pc;
	    strcpy (pc->cmd, c.c_str ());
	    json jnul = nullptr;
	    json v = (a.at (cinc).find ("data") != a.at (cinc).end ()) ? a.at (cinc).find ("data").value () : jnul;

	    if (pCommandChain == NULL)
		pCommandChain = pc;

	    pcmd_data pcmd_d = NULL;
	    pcmd_data prev_d = NULL;
	    string dp;
	    string dv;
	    if (v.is_object ())
	    {
		json::iterator i (&v);
		i = v.begin ();
		while (i != v.end ())
		{
		    pcmd_d = new_command_data ();
		    dp.assign (string (i.key ()));
		    memcpy (pcmd_d->parm_name, dp.c_str (), dp.length ());
		    if (i.value ().is_string ())
			dv.assign (i.value ());
		    else
			dv.assign (i.value ().dump ());

		    memcpy (pcmd_d->parm_value, dv.c_str (), dv.length ());
		    if (prev_d != NULL)
			prev_d->next = pcmd_d;
		    else
			pc->pdata = pcmd_d;

		    prev_d = pcmd_d;
		    i++;
		}
	    }
	    else
	    {
		if (prev_d != NULL)
		    prev_d->next = pcmd_d;
	    }

	    return parse_remote_commands (a, inc + 1, pc);
	}
    }
    catch (const std::invalid_argument&)
    {
	printf ("%s json parsing error. \n", __FUNCTION__);
	return -1;
    }

}

string makedirectory(string dirname, string indir)
{
    struct stat st = {0};

    if (dirname.empty () && indir.empty ())
    {
	return "";
    }

    if (stat (dirname.c_str (), &st) == -1)
    {
	mkdir (dirname.c_str (), 0700);
    }

    string newdir = dirname + "/" + indir;

    if (stat (newdir.c_str (), &st) == -1)
    {
	mkdir (newdir.c_str (), 0700);
    }

    return newdir;

}

RSA * createRSA(unsigned char * key, int publickey)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf (key, -1);
    if (keybio == NULL)
    {
	printf ("Failed to create key BIO\n");
	return 0;
    }
    if (publickey)
    {
	rsa = PEM_read_bio_RSA_PUBKEY (keybio, &rsa, NULL, NULL);
    }
    else
    {
	rsa = PEM_read_bio_RSAPrivateKey (keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL)
    {
	printf ("Failed to create RSA\n");
    }

    return rsa;
}

bool receive_sessionkey(pcmd c, char *response, pcomm_chain pConnection)
{
    string scmd;
    scmd.assign (c->cmd);
    if (scmd.compare ("sessionkeys") != 0) return false;
    string sessionkey;
    int bufsize = MEMSIZE;
    long key_length = 0;
    char *buffer = (char *) malloc (bufsize);
    memset (buffer, 0, bufsize);
    char *peerkey_buf = NULL;

    int n = 0;
    int total_bytes_received = 0;
    bool rc = true;

    auto begin = chrono::high_resolution_clock::now ();

    if (scmd.compare ("sessionkeys") == 0)
    {
	//cout << "receiving sessionkeys \n";
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string (d->parm_name);
		if (parm.compare ("sessionkey") == 0)
		{
		    //cout << "got server name : " << d->parm_value << endl;
		    sessionkey.assign (d->parm_value);
		}
		if (parm.compare ("key_length") == 0)
		{
		    //cout << "got filesize : " << d->parm_value << endl;
		    key_length = atol (d->parm_value);
		}
	    }
	    d = d->next;
	}

	strcpy (response, "OK\0");

	n = WRITE (pConnection->pthis->peer_public_rsa, pConnection, response, strlen (response));

	if (n < 0)
	{
	    cout << "@" << __FUNCTION__ << ">>";
	    perror ("ERROR writing to socket");
	    return false;
	}
    }

    auto end = chrono::high_resolution_clock::now ();
    auto dur = end - begin;

    double total_time = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count ();

    free (buffer);
    return rc;
}

bool receive_pubkey(pcmd c, unsigned char *response, pcomm_chain pConnection)
{
    string scmd;
    scmd.assign (c->cmd);
    if (scmd.compare ("mypubkey") != 0) return false;
    string servername;
    int bufsize = MEMSIZE;
    long filesize = 0;
    unsigned char *buffer = (unsigned char *) malloc (bufsize * sizeof (unsigned char));
    memset (buffer, 0, bufsize * sizeof (unsigned char));
    //unsigned char *peerkey_buf = NULL;

    int n = 0;
    int total_bytes_received = 0;
    bool rc = true;

    auto begin = chrono::high_resolution_clock::now ();

    if (scmd.compare ("mypubkey") == 0)
    {
	//cout << " receiving public key from server \n";
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string (d->parm_name);
		if (parm.compare ("servername") == 0)
		{
		    //cout << "got server name : " << d->parm_value << endl;
		    servername.assign (d->parm_value);
		}
		if (parm.compare ("filename") == 0)
		{
		    //cout << "got Filename : " << d->parm_value << endl;
		}
		if (parm.compare ("options") == 0)
		{
		    //cout << "got options : " << d->parm_value << endl;
		}
		if (parm.compare ("filesize") == 0)
		{
		    //cout << "got filesize : " << d->parm_value << endl;
		    filesize = atol (d->parm_value);
		}
	    }
	    d = d->next;
	}

	strcpy (response, "OK");

	n = WRITE (pConnection->pthis->peer_public_rsa, pConnection, response, strlen (response));

	if (n < 0)
	{
	    cout << "@" << __FUNCTION__ << ">>";
	    perror ("ERROR writing to socket");
	    return false;
	}

	while ((total_bytes_received < filesize) &&
	((n = READ (pLocalProc->my_private_rsa, pConnection, &buffer[total_bytes_received], bufsize)) > 0))
	{
	    if (n < 0)
	    {
		perror ("ERROR reading from socket");
		return false;
	    }

	    //cout << buffer;
	    total_bytes_received += n;

	    if ((pConnection->pthis->peer_public_key_string = malloc (sizeof (unsigned char) * total_bytes_received)) != NULL)
	    {
		strncpy (pConnection->pthis->peer_public_key_string, &buffer[0], total_bytes_received);
		pConnection->pthis->peer_public_key_len = total_bytes_received;
	    }
	    else
	    {
		return false;
	    }

	    add_key_to_db (&buffer[0], servername.c_str ());



	    //init_openssl();
	    BIO *pub = BIO_new_mem_buf (pConnection->pthis->peer_public_key_string, -1);
	    pConnection->pthis->EVP_key = PEM_read_bio_PUBKEY (pub, NULL, NULL, NULL);
	    pConnection->pthis->peer_public_rsa = EVP_PKEY_get1_RSA (pConnection->pthis->EVP_key);
	    BIO_set_close (pub, BIO_NOCLOSE);
	    BIO_free (pub);

	    //cout << "session keys set to NULL \n";
	    pConnection->pthis->session_key = NULL;
	    pConnection->pthis->session_iv = NULL;

	    cleanup_openssl ();

	    cout << "Communication with peer will be encrypted\n";
	}

    }
    else
    {
	memset (response, 0, MEMSIZE * sizeof (unsigned char));
	rc = false;
    }

    auto end = chrono::high_resolution_clock::now ();
    auto dur = end - begin;

    double total_time = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count ();
    //cout << "Time elapsed : " << total_time / 1000.0 << " seconds\n";


    free (buffer);
    return rc;
}

int send_file(char *directory, char *filename, pcomm_chain pConnection)
{
    // cout << "<< IN send_file()\n";
    int ret = 0;
    struct stat filestatbuf;
    int send_buff_limit = MEMSIZE;
    int bytes_sent = 0, total_sent = 0;
    string filepath;
    char filemode[10];

    filepath = string (directory) + "/" + string (filename);
    if (filestat (filepath, &filestatbuf, filemode))
    {
	try
	{
	    // open file and seek top
	    FILE *fp = fopen (filepath.c_str (), "r+");
	    fseek (fp, 0, SEEK_SET);

	    int receive_bffer_size = MEMSIZE;
	    int bytes_read = 0;
	    unsigned long filesize = filestatbuf.st_size;
	    unsigned char *send_buffer = (unsigned char*) mymalloc (sizeof (unsigned char)*send_buff_limit);
	    unsigned char *receive_bffer = (unsigned char *) mymalloc (sizeof (unsigned char)*receive_bffer_size);
	    memset (send_buffer, 0, send_buff_limit);
	    memset (receive_bffer, 0, receive_bffer_size);

	    // build prepare-to-receive json request
	    string prep2rec = "{\"1\":{\"response\":\"prep2rcvfile\",\"data\":{\"filename\":\"" + string (filename) + "\", \"filesize\":" + to_string (filesize) + "}}}";
	    //cout << "Sending back : " << prep2rec << endl;

	    // send prepare-to-receive json request
	    int rc = WRITE (pConnection->pthis->peer_public_rsa, pConnection, prep2rec.c_str (), prep2rec.length ());
	    //cout << "WRITE() returned : " << rc << endl;

	    // wait-receive acknowledgemnt/go ahead from client
	    rc = READ (pLocalProc->my_private_rsa, pConnection, receive_bffer, receive_bffer_size);

	    // Loop until all file is sent
	    while ((bytes_read = fread (send_buffer, 1, send_buff_limit, fp)) != 0)
	    {
		bytes_sent = WRITE (pConnection->pthis->peer_public_rsa, pConnection, send_buffer, bytes_read);

		total_sent += bytes_sent;

		// wait-receive acknowledgement from client 
		rc = READ (pLocalProc->my_private_rsa, pConnection, receive_bffer, receive_bffer_size);
	    }

	    cout << "Done sending!! Total sent = " << total_sent << endl;
	    free (send_buffer);
	    free (receive_bffer);
	    ret = 0;
	}

	catch (const std::runtime_error& re)
	{
	    // speciffic handling for runtime_error
	    std::cerr << "Runtime error: " << re.what () << std::endl;
	}
	catch (const std::exception& ex)
	{
	    // speciffic handling for all exceptions extending std::exception, except
	    // std::runtime_error which is handled explicitly
	    std::cerr << "Error occurred: " << ex.what () << std::endl;
	}
	catch (...)
	{
	    // catch any other errors (that we have no information about)
	    std::cerr << "Unknown failure occurred. Possible memory corruption" << std::endl;
	}
    }
    else
    {
	cout << "file " << filepath << " does not exist" << endl;
	ret = -1;
    }
    return ret;
}

bool sys_call_response(pcmd c, unsigned char *response, pcomm_chain pConnection)
{
    string scmd;
    scmd.assign (c->cmd);
    if (scmd.compare ("sys_call_response") != 0) return false;
    bool rc = true;
    string str_error, str_message;
    int er = 0;
    if (scmd.compare ("sys_call_response") == 0)
    {
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string (d->parm_name);
		if (parm.compare ("error") == 0)
		{
		    //cout << "got Filename : " << d->parm_value << endl;
		    str_error = d->parm_value;
		    er = atoi (str_error.c_str ());
		}
		if (parm.compare ("message") == 0)
		{
		    //cout << "got filesize : " << d->parm_value << endl;
		    str_message = d->parm_value;
		}
	    }
	    d = d->next;
	}

	// if No errors, start remote command protocol 
	if (er == 0)
	{
	    // Process remote command exchange
	    strcpy (response, "OK\0");
	    int n = WRITE (pConnection->pthis->peer_public_rsa, pConnection, response, strlen (response));

	    if (n < 0)
	    {
		cout << "@" << __FUNCTION__ << ">>";
		perror ("ERROR writing to socket");
		return false;
	    }
	    // Receive remote command data
	    if ((n = READ (pLocalProc->my_private_rsa, pConnection, response, MEMSIZE)) > 0)
	    {
		cout << response << endl;

		// Receive the final "OK" 
		if ((n = READ (pLocalProc->my_private_rsa, pConnection, response, MEMSIZE)) > 0)
		{
		    if (strncmp (response, "OK", 2) == 0)
			rc = true;
		    else
		    {
			cout << "Protocol error" << endl;
			rc = false;
		    }
		}
		else
		{
		    perror ("ERROR reading from socket");
		    return false;
		}
	    }
	    else
	    {
		perror ("ERROR reading from socket");
		return false;
	    }
	}
	else
	{
	    cout << "Remote message : " << str_message << endl;
	    return true;
	}
    }
    return rc;
}

bool receive_file(pcmd c, unsigned char *response, unsigned char *savedirectory, unsigned char *savefilename, pcomm_chain pConnection)
{
    string scmd;
    scmd.assign (c->cmd);
    if (scmd.compare ("prep2rcvfile") != 0) return false;
    int bufsize = MEMSIZE;
    unsigned char *buffer = (unsigned char*) malloc (sizeof (unsigned char) * bufsize);
    long filesize = 0;
    memset (buffer, 0, bufsize);
    char mysavefilename[100];

    int n = 0;
    int total_bytes_received = 0;
    bool rc = true;

    auto begin = chrono::high_resolution_clock::now ();

    if (scmd.compare ("prep2rcvfile") == 0)
    {
	pcmd_data d = c->pdata;
	while (d)
	{
	    if (d->parm_name != NULL)
	    {
		string parm = string (d->parm_name);
		if (parm.compare ("filename") == 0)
		{
		    //cout << "got Filename : " << d->parm_value << endl;
		}
		if (parm.compare ("filesize") == 0)
		{
		    //cout << "got filesize : " << d->parm_value << endl;
		    filesize = atol (d->parm_value);
		}
	    }

	    d = d->next;
	}

	if (savefilename == NULL)
	{
	    strcpy (mysavefilename, d->parm_value);
	}
	else
	{
	    strcpy (mysavefilename, savefilename);
	}

	boost::filesystem::path p (mysavefilename);
	string indirectory = p.parent_path ().string ();
	string filename_only = p.filename ().string ();

	indirectory.assign (pConnection->pthis->comm.hostname);
	indirectory.append (to_string (pConnection->pthis->comm.portno));
	string fulldir = makedirectory (string ((char *) savedirectory), indirectory);

	if (fulldir.empty ())
	{
	    cout << "Unable to create directory '" << savedirectory << "/" << indirectory << "'" << endl;
	    return false;
	}

	string filepath = fulldir + "/" + filename_only;

	FILE* infile = fopen (filepath.c_str (), "w+");
	if (infile == NULL)
	{
	    unsigned char error[100];
	    sprintf (error, "File open error '%s'", filepath.c_str ());
	    perror (error);
	    return false;
	}

	strcpy (response, "OK\0");

	n = WRITE (pConnection->pthis->peer_public_rsa, pConnection, response, strlen (response));

	if (n < 0)
	{
	    cout << "@" << __FUNCTION__ << ">>";
	    perror ("ERROR writing to socket");
	    return false;
	}
	bzero (buffer, bufsize);
	while ((total_bytes_received < filesize) &&
	((n = READ (pLocalProc->my_private_rsa, pConnection, buffer, bufsize)) > 0))
	{
	    if (n < 0)
	    {
		perror ("ERROR reading from socket");
		return false;
	    }

	    fwrite (buffer, 1, n, infile);

	    buffer[n] = '\0';
	    //cout << buffer;
	    total_bytes_received += n;

	    // show bytes received on terminal
	    printf ("\33[2K\r");
	    printf ("Received %d out of %d", total_bytes_received, filesize);
	    fflush (stdout);

	    strcpy (response, "OK\0");
	    n = WRITE (pConnection->pthis->peer_public_rsa, pConnection, response, strlen (response));
	    bzero (buffer, bufsize);
	}
	fclose (infile);

	printf ("\nTotal bytes received from server (%d bytes) \n", total_bytes_received);
	READ (pLocalProc->my_private_rsa, pConnection, buffer, bufsize);
	if (strncmp (buffer, "OK", 2) == 0)
	{
	    rc = true;
	}
	else
	{
	    rc = false;
	}

	auto end = chrono::high_resolution_clock::now ();
	auto dur = end - begin;

	double total_time = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count ();
	cout << "Time elapsed : " << total_time / 1000.0 << " seconds\n";


    }
    else
    {
	if (scmd.compare ("error") == 0)
	{
	    pcmd_data d = c->pdata;
	    while (d)
	    {
		if (d->parm_name != NULL)
		{
		    string parm = string (d->parm_name);
		    if (parm.compare ("error") == 0)
		    {
			cout << "Error : " << d->parm_value << endl;
		    }
		    if (parm.compare ("message") == 0)
		    {
			cout << "Message : " << d->parm_value << endl;
		    }
		}
		d = d->next;
	    }
	}

	memset (response, 0, MEMSIZE);
	rc = false;
    }

    free (buffer);
    return rc;

}

inline bool filestat(const std::string& name, struct stat *pstatbuf)
{

    return (stat (name.c_str (), pstatbuf) == 0);
}

bool command_not_found(pcmd c, unsigned char *response)
{
    string scmd;
    scmd.assign (c->cmd);
    cout << "Command not supported : " << scmd << " data [ ";
    pcmd_data d = c->pdata;
    while (d)
    {
	if (d->parm_name != NULL) cout << " [ " << d->parm_name << " = ";
	if (d->parm_value != NULL) cout << d->parm_value << " ] ";
	d = d->next;
    }
    cout << endl;
    memset (response, 0, MEMSIZE);
    //strcpy(response, "{\"rc\":-1,\"msg\":\"json parsing error. malformed request\"}");
    return true;
}

bool server_error(pcmd c, unsigned char *response, int *ret, unsigned char *message)
{
    string scmd;
    scmd.assign (c->cmd);
    if (scmd.compare ("error") == 0)
    {
	pcmd_data d = c->pdata;
	while (d)
	{
	    string parm = string (d->parm_name);
	    if (parm.compare ("error") == 0)
		*ret = atoi (d->parm_value);
	    if (parm.compare ("message") == 0)
		strcpy (message, d->parm_value);
	    d = d->next;
	}
	return true;
    }
    else
    {
	memset (response, 0, MEMSIZE);
	return false;
    }
}

void set_last_error(int set_errno, const char * message)
{
    pLocalProc->last_error.errorno = set_errno;
    strncpy (pLocalProc->last_error.message, message, sizeof (pLocalProc->last_error.message));
}

void print_last_error()
{
    if (pLocalProc->last_error.errorno != 0)
    {
	//cout << "Peer returned message\n";
	cout << "-- Error No ; " << pLocalProc->last_error.errorno << endl;
	cout << "-- Message  ; " << pLocalProc->last_error.message << endl;
    }
}

void print_last_error_reset()
{
    print_last_error ();
    // Clear last error message
    pLocalProc->last_error.errorno = 0;
    memset (pLocalProc->last_error.message, 0, sizeof (pLocalProc->last_error.message));
}

int exec_commands(unsigned char *response, int *ret, unsigned char *message, pcomm_chain pConnection)
{
    if (pCommandChain == NULL)
	return -1;

    pcmd c = pCommandChain;
    while (c != NULL && c->cmd != NULL)
    {
	// cout << " Command *** : " << c->cmd << endl;
	if (receive_file (c, response, DOWNLOAD_DIR, c->pdata->parm_value, pConnection))
	    goto NEXTCOMMAND;
	if (receive_pubkey (c, response, pConnection))
	    goto NEXTCOMMAND;
	if (receive_sessionkey (c, response, pConnection))
	    goto NEXTCOMMAND;
	if (sys_call_response (c, response, pConnection))
	    goto NEXTCOMMAND;
	if (server_error (c, response, &pLocalProc->last_error.errorno, pLocalProc->last_error.message))
	{
	    goto NEXTCOMMAND;
	}
	else command_not_found (c, response);

NEXTCOMMAND:
	c = c->next;
    }

    return 1;
}

int process_remote_request(unsigned char *input, unsigned char * response, int *comret, unsigned char *message, pcomm_chain pConnection)
{
    typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
    std::string sbuf ((char *) input);
    boost::char_separator<char> sep (" ");
    tokenizer tokens (sbuf, sep);
    tokenizer::iterator token = tokens.begin ();

    bool parseError = false;
    int protocol = NATIVE_PROTO;
    int ret = 0;
    unsigned char *msg = NULL;
    if (!input) // empty input, exit
	goto cleanup;

    //cout << "Response : " << input << endl;
    if (strcmp (input, "OK") == 0)
	return 0;

    //int rc_resp = 0;

    // Create message buffer for local Servent client
    msg = (char*) malloc (1024);
    if (msg == NULL)
    {
	perror ("msg");
	goto cleanup;
    }

    // ******************************************************
    // Identify protocol
    protocol = identify_protocol (sbuf);

    //cout << "About to tokenize ..\n";
    // *******************************************************
    // Start tokenizing

    switch (protocol)
    {
	case NATIVE_PROTO:
	    try
	    {
		pCommandChain = NULL;
		json jinput;
		try
		{
		    jinput = json::parse (input);
		}
		catch (const std::invalid_argument&)
		{
		    cout << "Invalid response from peer" << endl;
		    parseError = true;
		}
		//cout << " Going to parse command \n";
		if (parse_remote_commands (jinput, 1, NULL) != -1)
		{
		    parseError = exec_commands (response, comret, message, pConnection) == -1;

		    dump_command (pCommandChain);
		}
		else
		{
		    cout << "parse_remote_commands() failed" << endl;
		    parseError = true;
		}
		freeCommandChain (pCommandChain);
	    }
	    catch (const std::invalid_argument&)
	    {
		parseError = true;
	    }
	    fflush (stdout);

	    if (parseError)
	    {
		strcpy (response, "{\"rc\":-1,\"msg\":\"json parsing error. malformed request\"}");
		printf ("error parsing response \n");
	    }

	    // force a response if empty
	    if (!strlen (response))
		strcpy (response, "OK\0");

	    break;
	default:
	    break;
    }

    // ****************** Clean up and exit ********************************
cleanup:
    if (msg)
    {
	free (msg);
	msg = NULL;
    }
    //printf("\n\n<< Out of process_remote_request()\n");
    return ret;
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++)
    {
	printf ("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf ("\n");
    return 0;
}

static int sqlite3callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++)
    {
	printf ("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf ("\n");
    return 0;
}

int add_key_to_db(unsigned char *key, unsigned char * peername)
{
    int rc = 0;
    const unsigned char *dbpeername;
    unsigned char *zErrMsg;
    sqlite3_stmt *stmt;

    rc = sqlite3_prepare_v2 (pLocalProc->db,
	    "SELECT SERVER_NAME  FROM SERVERSKEYS WHERE SERVER_NAME = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
	fprintf (stderr, "SQL error: %s\n", zErrMsg);
	sqlite3_finalize (stmt);
	sqlite3_free (zErrMsg);
	return -1;
    }

    rc = sqlite3_bind_text (stmt, 1, peername, strlen (peername), SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
	sqlite3_finalize (stmt);
	fprintf (stderr, "SQL error: %s\n", zErrMsg);
	sqlite3_free (zErrMsg);
	return -1;
    }

    rc = sqlite3_step (stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
    {
	sqlite3_finalize (stmt);
	fprintf (stderr, "SQL error: %s\n", zErrMsg);
	sqlite3_free (zErrMsg);
	return -1;
    }

    if (rc == SQLITE_DONE)
    {
	// no more records
	dbpeername = sqlite3_column_text (stmt, 0);

	if (dbpeername == NULL || strcmp (dbpeername, peername) != 0)
	{
	    string sql = string ("INSERT INTO SERVERSKEYS (KEY, SERVER_NAME,LASTADDRESS) VALUES ( ") +
		    string ("\"") +
		    string ((char *) key) +
		    string ("\",\"") +
		    string ((char *) peername) +
		    string ("\",\"\" ") +
		    string (")");

	    /* Execute SQL statement */
	    rc = sqlite3_exec (pLocalProc->db, sql.c_str (), sqlite3callback, 0, &zErrMsg);
	    if (rc != SQLITE_OK)
	    {
		fprintf (stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free (zErrMsg);
	    }

	    sqlite3_finalize (stmt);
	    return 1;
	}
	else
	{
	    //cout << "Peer " << peername << " is already in database \n";
	    return 0;
	}
    }
    return 0;

}

int create_key_table(sqlite3 *db, unsigned char *zErrMsg)
{
    unsigned char *sql;
    int rc = 0;
    /* Create SQL statement */
    sql = "CREATE TABLE IF NOT EXISTS SERVERSKEYS("  \
         "ID INTEGER PRIMARY KEY  AUTOINCREMENT," \
         "KEY           TEXT    NOT NULL," \
         "SERVER_NAME   VARCHAR(100)     NOT NULL," \
         "LASTADDRESS   VARCHAR(50) " \
         " );";

    /* Execute SQL statement */
    rc = sqlite3_exec (db, sql, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK)
    {
	fprintf (stderr, "SQL error: %s\n", zErrMsg);
	sqlite3_free (zErrMsg);
    }
}

bool check_usage(int argc, char *argv[])
{

    if (argc < 3)
    {
	fprintf (stderr, "usage %s hostname port\n", argv[0]);
	//return false;
    }
    return true;
}

void closesqlitedb(sqlite3 * db)
{
    if (db != NULL)
	sqlite3_close (db);
}

sqlite3 * initsqllitedb(void)
{
    sqlite3 *db = NULL;
    unsigned char *zErrMsg = 0;

    int rc = sqlite3_open ("cdata", &db);

    if (rc)
    {
	fprintf (stderr, "Can't open database: %s\n", sqlite3_errmsg (db));
	return (0);
    }
    else
    {
	//fprintf(stderr, "Opened database successfully\n");
    }

    create_key_table (db, zErrMsg);

    return db;
}

bool rsa_gen_keys_in_memory(RSA **my_private_rsa, unsigned char **public_key_string, long * pklen)
{
    int ret = 0;
    //BIO *bio_private = NULL;
    BIO *bio_public = NULL;
    int bits = 4096;

    //init_openssl();

    //char *private_key_text, *public_key_text;

    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    // Get the context
    ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, NULL);
    if (!ctx)
	goto cleanup;

    // init keygen
    if (EVP_PKEY_keygen_init (ctx) <= 0)
	goto cleanup;

    // set the bit size 
    if (EVP_PKEY_CTX_set_rsa_keygen_bits (ctx, bits) <= 0)
	goto cleanup;

    /* Generate key */
    if (EVP_PKEY_keygen (ctx, &pkey) <= 0)
	goto cleanup;

    *my_private_rsa = EVP_PKEY_get1_RSA (pkey);


    if (RSA_check_key (*my_private_rsa))
    {
	printf ("RSA key is valid.\n");
    }
    else
    {
	printf ("Error validating RSA key.\n");
	handle_openssl_error ();
	return false;
    }

    // write private key to memory
    //    bio_private = BIO_new(BIO_s_mem());
    //    ret = PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    //    if (ret != 1)
    //    {
    //	goto cleanup;
    //    }
    //    BIO_flush(bio_private);
    //    BIO_get_mem_data(bio_private, &private_key_string);
    //    cout << "PRIVE KEY :\n" << private_key_text << endl;

    // write public key to memory
    bio_public = BIO_new (BIO_s_mem ());
    ret = PEM_write_bio_PUBKEY (bio_public, pkey);
    if (ret != 1)
    {
	goto cleanup;
    }
    BIO_flush (bio_public);

    *pklen = BIO_get_mem_data (bio_public, public_key_string);


cleanup:

    if (pkey) EVP_PKEY_free (pkey);

    cleanup_openssl ();
    return ret;
}

int init_client(int argc, char *argv[])
{
    pLocalProc = NULL;

    // allocate global data
    pLocalProc = (pproc_data) mymalloc (sizeof (proc_data));
    if (pLocalProc == NULL)
	goto cleanup;

    memset (pLocalProc, 0, sizeof (proc_data));
    strcpy (pLocalProc->myname, MY_DEFAULT_NAME);

    // Init db
    if ((pLocalProc->db = initsqllitedb ()) == NULL)
	goto cleanup;

    if (rsa_gen_keys_in_memory (&pLocalProc->my_private_rsa, &pLocalProc->mypublic_key_string, &pLocalProc->mypublic_key_len) != 1)
	goto cleanup;


    // run client
    if (run_client (argc, argv, pLocalProc->db) == -1)
	goto cleanup;

cleanup:
    if (pLocalProc != NULL)
    {
	if (pLocalProc->db != NULL)
	    closesqlitedb (pLocalProc->db);
	free (pLocalProc);
    }
}

int main(int argc, char *argv[])
{
    if (!check_usage (argc, argv))
	exit (-1);

    init_client (argc, argv);
}

bool connect_host_error()
{
    bool rc = true;
    switch (h_errno)
    {
	case HOST_NOT_FOUND:
	    cout << "The specified host is unknown.\n";
	    rc = false;
	    break;
	case NO_DATA:
	    cout << "The requested name is valid but does not have an IP address.\n";
	    rc = false;
	    break;
	case NO_RECOVERY:
	    cout << "A nonrecoverable name server error occurred.\n";
	    rc = false;
	    break;
	case TRY_AGAIN:
	    cout << "A temporary error occurred on an authoritative name server. Try again later.\n";
	    rc = false;
	    break;
	default:
	    rc = true;
    }
    return rc;
}

struct hostent *gethostbyname_r_wrap(const string& hostname)
//vector<hostent> gethostbyname_r_wrap( const string& hostname )
{
    char *tmp;
    int tmplen = 1024;
    struct hostent hostbuf, *hp;
    int herr, hres;
    vector<hostent> result;
    result.clear ();

    tmp = reinterpret_cast<char*> (malloc (tmplen));
    if (tmp == NULL)
    {
	throw bad_alloc ();
    }
    try
    {
	while ((hres = gethostbyname_r (hostname.c_str (), &hostbuf,
		tmp, tmplen, &hp, &herr)) == ERANGE)
	{
	    // realloc
	    tmplen *= 2;
	    char* tmp1 =
		    reinterpret_cast<char*> (realloc (tmp, tmplen));
	    if (!tmp1)
	    {
		// OOM?
		tmplen /= 2;
		tmplen += 64;
		tmp1 =
			reinterpret_cast<char*> (realloc (tmp, tmplen));
		if (!tmp1)
		{ // OOM!
		    throw bad_alloc ();
		}
	    }

	    tmp = tmp1;

	}

	if (NULL == hp)
	{
	    // error translation.
	    switch (herr)
	    {
		case HOST_NOT_FOUND:
		    cout << "The specified host " << hostname << " is unknown.\n";
		    break;
		case NO_ADDRESS:
		    cout << "The requested name is valid but does not have an IP address.\n";
		    break;
		case NO_RECOVERY:
		    cout << "A nonrecoverable name server error occurred.\n";
		    break;
		case TRY_AGAIN:
		    cout << "A temporary error occurred on an authoritative name server. Try again later.\n";
		    break;
		default:
		    cout << "Unknown error code from gethostbyname_r for " << hostname << endl;
		    break;
	    }
	}
	else
	{
	    char** pAddr = hp->h_addr_list;

	    // result.push_back ( hostbuf );
	    //	cout << result[0].h_name << endl;

	    char buffer[1024];
	    while (*pAddr)
	    {
		snprintf (buffer, 1024, "%u.%u.%u.%u",
			static_cast<unsigned int> (
						static_cast<unsigned char> ((*pAddr)[0])),
			static_cast<unsigned int> (
						static_cast<unsigned char> ((*pAddr)[1])),
			static_cast<unsigned int> (
						static_cast<unsigned char> ((*pAddr)[2])),
			static_cast<unsigned int> (
						static_cast<unsigned char> ((*pAddr)[3])));
		cout << buffer << endl;
		////            result.push_back(string(buffer));
		++pAddr;
	    }
	}
    }
    catch (...)
    {
	free (tmp);
    }
    free (tmp);
    return hp;
}

bool init_comm(unsigned char *hostname, int portno, pcomm_chain pConnection)
{
    // Init tcp communication
    struct hostent hent;
    vector<hostent> host_list;
    host_list.clear ();
    signal (SIGPIPE, SIG_IGN); // ignore sigpipe signals    
    memset (&pConnection->pthis->comm, 0, sizeof (tcpcomm));

    pConnection->pthis->comm.server = NULL;

    //memset(&pConnection->pthis->comm.serv_addr, 0, sizeof(sockaddr_in)); 

    pConnection->pthis->comm.portno = portno;

    pConnection->pthis->comm.sockfd = socket (AF_INET, SOCK_STREAM, 0);

    if (pConnection->pthis->comm.sockfd < 0)
    {
	perror ("ERROR opening socket");
	return false;
    }

    //    host_list = gethostbyname_r_wrap ( ( char * ) hostname );
    //    hent = host_list[0];
    //   
    //    pConnection->pthis->comm.server = gethostbyname_r_wrap ( ( char * ) hostname );	    
    //    if ( host_list.size ( ) > 0 )
    //    {
    //	//pConnection->pthis->comm.server = mymalloc(sizeof(struct hostent));
    //	pConnection->pthis->comm.server->h_addr_list =  hent.h_addr_list;
    //    }
    //    else
    //	return false;

    pConnection->pthis->comm.server = gethostbyname ((char *) hostname);
    if (pConnection->pthis->comm.server == NULL || !connect_host_error ())
    {
	fprintf (stderr, "ERROR, no such host\n");
	return false;
    }

    bzero ((char *) &pConnection->pthis->comm.serv_addr, sizeof (pConnection->pthis->comm.serv_addr));

    pConnection->pthis->comm.serv_addr.sin_family = AF_INET;
    bcopy ((char *) pConnection->pthis->comm.server->h_addr,
	    (char *) &pConnection->pthis->comm.serv_addr.sin_addr.s_addr,
	    pConnection->pthis->comm.server->h_length);

    pConnection->pthis->comm.serv_addr.sin_port = htons (pConnection->pthis->comm.portno);

    pConnection->pthis->comm.status = 0; // UNCONNECTED 

    return true;
}

int get_command_line(unsigned char *client_buffer, int *buffer_len, std::string promp_host)
{
    cout << promp_host;
    // clear client buffer
    bzero (client_buffer, CLIENT_BUFFER_SIZE);

    // read and size client message
    fgets (client_buffer, CLIENT_BUFFER_SIZE - 1, stdin);

    *buffer_len = strlen (client_buffer) - 1;
    if (*buffer_len == 0)
	return 0;

    if (strncmp (client_buffer, (const char *) QUIT_CLIENT_CHARS, *buffer_len) == 0)
	return -1;

    return 0;
}

int send_message_to_peer(unsigned char *client_buffer, int message_length, pcomm_chain pConnection)
{
    //Send client input to peer
    //int sent_data_length = WRITE(pLocalProc->peer_public_rsa, pLocalProc->comm.sockfd, client_buffer, message_length);    
    int sent_data_length = WRITE (pConnection->pthis->peer_public_rsa, pConnection, client_buffer, message_length);

    if (sent_data_length < 0)
    {
	cout << "@" << __FUNCTION__ << ">>";
	perror ("ERROR writing to socket");
	return -1;
    }
    return sent_data_length;
}

int receive_response_from_peer(unsigned char *client_buffer, pcomm_chain pConnection)
{
    //Recieve response from peer
    bzero (client_buffer, CLIENT_BUFFER_SIZE);
    int response_length = READ (pLocalProc->my_private_rsa, pConnection, client_buffer, CLIENT_BUFFER_SIZE);
    if (response_length < 0)
    {
	perror ("ERROR reading from socket");
	return -1;
    }

    //printf("Received from server (%d bytes): %s\n", response_length, client_buffer);
    return response_length;
}

int SENDHANDSHAKE(pcomm_chain pConnection)
{
    int rc = 0, response_length = 0;
    char client_buffer[CLIENT_BUFFER_SIZE];
    char *response = NULL;
    int serverret = 0;
    char servermessage[100];
    int sent_data_length = 0;
    //char str_handshake[];
    string handshake;
    string myname, original;
    original = string (pLocalProc->myname);

    if (original.compare (MY_DEFAULT_NAME) == 0)
	myname.assign (pLocalProc->myname);
    else
	myname.assign (original);

    handshake = string ("{\"1\":{\"command\":\"handshake\",\"data\":{\"Iam\":\"") +
	    myname +
	    string ("\",\"clientkey\":\"prep2recv\"}}}");

    RSA * tmpMyPriv_rsa = pLocalProc->my_private_rsa;

    // Get response memory
    response = (unsigned char *) malloc (MEMSIZE * sizeof (unsigned char));
    if (response != NULL)
    {
	// clear response memory
	memset (response, 0, MEMSIZE * sizeof (unsigned char));

	// Send "prep2recv" client key to server
	// Send unencrypted
	if ((sent_data_length = WRITE (NULL, pConnection, handshake.c_str (), handshake.length ())) != -1)
	{
	    // wait and get peer response
	    pLocalProc->my_private_rsa = NULL;
	    // Receive unencrypted
	    if ((response_length = receive_response_from_peer (client_buffer, pConnection)) != -1)
	    {
		// expecting OK that server is now prepped to recv client key
		if (strcmp (client_buffer, "OK") == 0)
		{
		    // Send client public key
		    if ((sent_data_length = WRITE (pConnection->pthis->peer_public_rsa, pConnection,
		    pLocalProc->mypublic_key_string, pLocalProc->mypublic_key_len)) != -1)
		    {
			// expecting only "OK" response
			// receive ENCRYPTED 
			pLocalProc->my_private_rsa = tmpMyPriv_rsa;
			if ((response_length = receive_response_from_peer (client_buffer, pConnection)) != -1)
			{
			    if (process_remote_request (client_buffer, response, &serverret, servermessage, pConnection) == -1)
				rc = -1;
			    else
			    {
				if (serverret != 0)
				    cout << servermessage << endl;
			    }
			    print_last_error_reset ();
			}
			else rc = -1;
		    }
		    else rc = -1;
		}
		else rc = -1;

		// get session keys
		string request ("{\"1\":{\"command\":\"getkeys\",\"data\":{\"parm\":\"none\"}}}");

		// clear response memory
		memset (response, 0, MEMSIZE * sizeof (unsigned char));

		if ((sent_data_length = WRITE (pConnection->pthis->peer_public_rsa, pConnection, request.c_str (), request.length ())) != -1)
		{
		    // wait and get peer response
		    if ((response_length = receive_response_from_peer (client_buffer, pConnection)) != -1)
		    {
			pConnection->pthis->session_key = client_buffer;
			pConnection->pthis->session_key_len = response_length;

			pConnection->pthis->session_rsa = (char *) mymalloc (KEY_SIZE);
			pConnection->pthis->session_iv = (char *) mymalloc (BLOCK_SIZE);
			memset (pConnection->pthis->session_rsa, 0, KEY_SIZE);
			memset (pConnection->pthis->session_iv, 0, BLOCK_SIZE);
			set_session_key (pConnection->pthis->session_key, pConnection->pthis->session_key_len, pConnection);

		    }
		    else rc = -1;

		}
		else rc = -1;
	    }
	    else rc = -1;
	}
	else rc = -1;
    }
    else rc = -1;

    free (response);
    return rc;
}

pcomm_chain search_connections_by_alias(char * alias)
{
    pcomm_chain ch = pLocalProc->CommHook.pChainStart;
    while (ch != NULL && strcmp (ch->pthis->comm.alias, alias) != 0)
    {
	ch = ch->next;
    }
    return ch;
}

pcomm_chain search_connections_by_hostname(char * hostname, int port)
{
    pcomm_chain ch = pLocalProc->CommHook.pChainStart;
    while (ch != NULL &&
	   (strcmp (ch->pthis->comm.hostname, hostname) != 0 || ch->pthis->comm.portno != port))
    {
	ch = ch->next;
    }
    return ch;
}

int disconnect_from_peer(pcomm_chain *pConnection)
{
    if (*pConnection == NULL) return -1;
    shutdown ((*pConnection)->pthis->comm.sockfd, SHUT_WR); /* inform remote that we are done */
    //depleteSendBuffer ( ( *pConnection )->pthis->comm.sockfd );
    close ((*pConnection)->pthis->comm.sockfd);
    if (!delete_comm_link (pConnection))
	return -1;

    *pConnection = NULL;
    return 0;
}

int disconnect_all_hosts()
{
    pcomm_chain ch = pLocalProc->CommHook.pChainStart;
    while (ch != NULL)
    {
	disconnect_from_peer (&ch);
	ch = pLocalProc->CommHook.pChainStart;
    }
    return 0;
}

int disconnect_by_alias(char* alias)
{
    pcomm_chain ch = search_connections_by_alias (alias);
    return disconnect_from_peer (&ch);
}

int reconnect_to_peer(unsigned char *hostname, int portno)
{
    cout << "Attempting to reconnect to " << hostname << endl;
}

int connect_to_peer(unsigned char *hostname, int portno, pcomm_chain *pConnection)
{
    // is NO Encryption (noenc) requested?
    //pLocalProc->comm.encrypt = is_communication_encrypted(argc, argv);
    pcomm_chain ch = NULL;
    if ((ch = search_connections_by_hostname (hostname, portno)) != NULL)
    {
	*pConnection = ch;
	return 0;
    }

    if ((*pConnection = add_comm_link ()) == NULL)
	return -1;

    if (!init_comm (hostname, portno, *pConnection))
    {
	delete_comm_link (pConnection);
	*pConnection = NULL;
	goto cleanup;
    }

    strcpy ((*pConnection)->pthis->comm.hostname, hostname);
    (*pConnection)->pthis->comm.portno = portno;

    if (connect ((*pConnection)->pthis->comm.sockfd,
	(struct sockaddr *) &(*pConnection)->pthis->comm.serv_addr,
	sizeof ((*pConnection)->pthis->comm.serv_addr)) < 0)
    {
	perror ("ERROR connecting");
	delete_comm_link (pConnection);
	*pConnection = NULL;
	return -1;
    }
    (*pConnection) ->pthis->comm.status = 1; // CONNECTED
    cout << "Connected to " << hostname << endl;
    return SENDHANDSHAKE (*pConnection);

cleanup:
    return -1;
}

bool is_communication_encrypted(int argc, char *argv[])
{
    // encrypt by default if 'noenc' is NOT requested
    for (int k = 1; k < argc; k++)
    {
	if (strcmp (argv[k], "noenc") == 0)
	    return false;
    }
    return true;
}

// trim from start

static inline std::string &ltrim(std::string &s)
{
    s.erase (s.begin (), std::find_if (s.begin (), s.end (),
	    std::not1 (std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end

static inline std::string &rtrim(std::string &s)
{
    s.erase (std::find_if (s.rbegin (), s.rend (),
	    std::not1 (std::ptr_fun<int, int>(std::isspace))).base (), s.end ());
    return s;
}

// trim from both ends

static inline std::string &trim(std::string &s)
{
    return ltrim (rtrim (s));
}

bool validate_com_arg(string command, vector<string>::iterator tok, vector<string>::iterator end, string &request, string& error)
{
    if (command == string ("get"))
    {
	++tok;
	if (tok != end)
	{
	    string arg (*tok);
	    trim (arg);

	    // Get a file
	    if (arg.compare ("file") == 0)
	    {
		++tok;
		if (tok != end)
		{
		    string filename (*tok);
		    ++tok;
		    string options;
		    if (tok != end)
		    {
			options.assign (*tok);
			trim (options);
		    }
		    else
		    {
			options.assign ("--------");
		    }
		    trim (filename);

		    if (filename.empty ())
		    {
			error.assign ("Error: filename is required");
			return false;
		    }

		    request = string ("{\"1\":{\"command\":\"getfile\",\"data\":{\"filename\":\"") +
			    filename +
			    string ("\", \"options\": \"") +
			    options +
			    string ("\"}}}");

		    error.clear ();
		    return true;

		}
		else
		{
		    error.assign ("syntax: \"get file <filename> [options]\" ");
		    cout << error << endl;
		    return false;
		}
	    }

		// Get testdata
	    else if (arg.compare ("testdata") == 0)
	    {
		request = string ("{\"1\":{\"command\":\"getdata\",\"data\":{\"type\":\"") +
			"binary" +
			string ("\", \"options\": \"") +
			"-------" +
			string ("\"}}}");

		cout << "token : " << request << endl;
		error.clear ();
		return true;
	    }
		// Get nothing should print out usage message for all get options
	    else
	    {
		error.assign ("syntax:\n \"get file <filename> [options]\" \n \"get testdata \"");
		//cout << error << endl;
	    }
	}
	else
	{
	    error.assign ("syntax:\n \"get file <filename> [options]\" \n \"get testdata \"");
	    return false;
	}
    }
    else if (command == string ("run"))
    {

	++tok;
	if (tok != end)
	{
	    string sys_call (*tok);
	    string sys_call_options;
	    trim (sys_call);

	    ++tok;
	    while (tok != end)
	    {
		sys_call_options.append (*tok);

		sys_call_options.append (" ");
		++tok;
	    }
	    sys_call_options = trim (sys_call_options);
	    request = string ("{\"1\":{\"command\":\"system\",\"data\":{\"sys_call\":\"") +
		    sys_call +
		    string ("\", \"options\": \"") +
		    sys_call_options +
		    string ("\"}}}");
	    //cout << request << endl;

	    error.clear ();
	    return true;
	}
	else
	{
	    error.assign ("syntax:\n \"system <remote command> [options]\" \n");
	    //cout << error << endl;
	}
    }
}

string valid_command(const std::string & token)
{
    if (token.empty ())
	return "";

    string cmd = to_lower_copy (token);
    if (cmd == string ("get"))
	return "get";
    else if (cmd == string ("run") || cmd == string ("r"))
	return "run";
    else
    {
	set_last_error (-1, "Invalid remote request");
	return "";
    }
}

int build_request_message(unsigned char *client_buffer, int *message_len, pcomm_chain pConnection)
{
    int token_count = 0;
    int i = 0;
    *message_len = 0;
    string line ((char *) client_buffer);
    string command;
    string request;
    int rc = 0;
    vector<string> tokens;
    boost::split (tokens, line, boost::is_any_of (" "));

    token_count = tokens.size ();
    vector<string>::iterator tok = tokens.begin ();
    string cmd = string (*tok);
    command = valid_command (trim (cmd));
    if (!command.empty ())
    {
	//string arg = string(*(++tok));
	string error;
	validate_com_arg (command, tok, tokens.end (), request, error);

	if (!error.empty ())
	    cout << "command : " << command << " >> " << error << endl;
	else
	{
	    *message_len = request.length ();
	    strcpy (client_buffer, request.c_str ());
	}
    }
    else
    {
	memset (client_buffer, 0, CLIENT_BUFFER_SIZE);
	cout << "Invalid command \"" << trim (cmd) << "\"" << endl;
	//rc = -1;
    }
    return rc;
}

int process_local_commands(char *input, int *mlength, pcomm_chain *pConnection)
{
    int rc = 0;

    int token_count = 0;
    int i = 0;
    *mlength = 0;
    string line ((char *) input);
    string command;
    string request;
    vector<string> tokens;
    boost::split (tokens, line, boost::is_any_of (" "));

    token_count = tokens.size ();
    vector<string>::iterator tok = tokens.begin ();
    string cmd = to_lower_copy (string (trim (*tok)));
    //cout << cmd << endl;
    if (cmd.empty ())
	return false;

    int k = 0;
    unsigned int nArgs = 40;
    string Args[nArgs];

    while (++tok != tokens.end ())
    {
	Args[k] = to_lower_copy (string (*tok));
	k++;
    }

    //command = valid_command(trim(cmd));
    if (!cmd.empty ())
    {
	if (cmd.compare ("connect") == 0)
	{
	    string host = Args[0];
	    string str_port = trim (Args[1]);
	    std::string::size_type sz;
	    int port;
	    if (str_port.empty ())
	    {
		string alias = trim (host);
		pcomm_chain ch = search_connections_by_alias (alias.c_str ());
		if (ch != NULL)
		{
		    *pConnection = ch;
		}
	    }
	    else if (isInteger (str_port))
	    {
		port = stoi (str_port, &sz);
		if (connect_to_peer ((unsigned char *) host.c_str (), port, pConnection) == -1)
		    rc = -1;
		else
		{
		    string alias = string ((*pConnection)->pthis->comm.hostname);
		    alias.append (to_string (((*pConnection)->pthis->comm.portno)));

		    strncpy ((*pConnection)->pthis->comm.alias, alias.c_str (), alias.length ());
		    (*pConnection)->pthis->comm.alias[alias.length ()] = '\0';

		    Args[2] = trim (Args[2]);
		    if (!Args[2].empty ())
		    {
			if (Args[2].compare ("as") == 0)
			{
			    if (!Args[3].empty ())
			    {
				Args[3] = trim (Args[3]);
				if (Args[3].length () <= NAME_SIZE)
				{
				    strncpy (&(*pConnection)->pthis->comm.alias[0], Args[3].c_str (), Args[3].length ());
				    (*pConnection)->pthis->comm.alias[Args[3].length ()] = '\0';
				}
				else
				{
				    strncpy (&(*pConnection)->pthis->comm.alias[0], Args[3].c_str (), NAME_SIZE);
				    (*pConnection)->pthis->comm.alias[NAME_SIZE] = '\0';
				}
			    }
			}

		    }
		}
	    }
	    else
	    {
		cout << "Port number must be a positive interger\n";
	    }
	    rc = 1;
	}
	else if (cmd.compare ("disconnect") == 0)
	{
	    string alias = trim (Args[0]);
	    if (alias.empty ())
	    {
		cout << "specify connection to disconnect or use 'current' or 'all' \n";
	    }
	    else
	    {
		if (alias == string ("current") && *pConnection != NULL)
		{
		    alias = string ((*pConnection)->pthis->comm.alias);
		    disconnect_by_alias (alias.c_str ());
		    *pConnection = search_connections_by_alias (alias.c_str ());
		    rc = 1;
		}
		else if (alias == string ("all"))
		{
		    disconnect_all_hosts ();
		    cout << "all hosts were disconnected \n";
		    rc = 1;
		}
		else
		{
		    pcomm_chain ptmpConn = search_connections_by_alias (alias.c_str ());
		    if (ptmpConn != NULL)
			disconnect_by_alias (alias.c_str ());
		    else
			cout << "connection not found \n";

		    rc = 1;
		}
	    }
	}
	else if (cmd.compare ("show") == 0)
	{
	    string show_type = trim (Args[0]);
	    if (show_type.compare ("connections") == 0)
	    {
		pcomm_chain ch = pLocalProc->CommHook.pChainStart;
		cout << "No." << "\tAlias" << "\t\Node" "\t\tPort No." << endl;
		for (k = 0; k < pLocalProc->CommHook.count; k++)
		{
		    cout << (k + 1) << "\t" << ch->pthis->comm.alias << "\t\t" << ch->pthis->comm.hostname << "\t\t" << ch->pthis->comm.portno << endl;
		    ch = ch->next;
		}
	    }
	    else if (show_type.compare ("myname") == 0)
	    {
		cout << pLocalProc->myname << endl;
	    }
	    else
	    {
		cout << "invalid " << endl;
	    }
	    rc = 1;
	}
	else if (cmd.compare ("set") == 0)
	{
	    string config_parm = Args[0];
	    config_parm = trim (config_parm);
	    if (!config_parm.empty ())
	    {
		if (config_parm.compare ("myname") == 0)
		{
		    string myname = Args[1];
		    myname = trim (myname);
		    if (!myname.empty ())
		    {
			strncpy (pLocalProc->myname, myname.c_str (), myname.length ());
			pLocalProc->myname[myname.length ()] = '\0';
		    }
		}
	    }
	    rc = 1;
	}
	else if (cmd.compare ("help") == 0)
	{
	    print_help ();
	    rc = 1;
	}
	else if (cmd.compare ("status") == 0)
	{
	    cout << "about to check and print status \n";
	    rc = 1;
	}
	else
	{
	    //set_last_error(-1, "Invalid command");
	    rc = 0;
	}
    }
    return rc;
}

pcomm_chain purge_and_set_connections(pcomm_chain pConnection, char *conn_alias, string& prompt_host)
{
    pcomm_chain pCurrConn = NULL;
    if (conn_alias[0] != 0)
    {
	// Old connection exists, test if it is still valid
	pcomm_chain pOldConn = search_connections_by_alias (conn_alias);

	// (1) Current connection changed, old connection is still valid
	if (pOldConn != NULL &&
	pConnection != NULL &&
	pConnection->pthis != NULL &&
	pConnection->pthis->comm.status == 1 &&
	(pConnection->pthis != pOldConn->pthis))
	{
	    // set alias to new connection    
	    prompt_host.assign (pConnection->pthis->comm.alias);
	    prompt_host.append (">>");
	    strcpy (conn_alias, pConnection->pthis->comm.alias);
	}
	    // Old connection is Gone!
	else if (pOldConn == NULL)
	{
	    // connection was lost, reset alias
	    conn_alias[0] = 0;
	    prompt_host.assign (PROMPT_TEXT);
	    pConnection = NULL;
	}
    }
    else
    {
	// First connection
	if (pConnection != NULL &&
	pConnection->pthis != NULL &&
	pConnection->pthis->comm.status == 1)
	{
	    // connection found	    
	    prompt_host.assign (pConnection->pthis->comm.alias);
	    prompt_host.append (">>");
	    strcpy (conn_alias, pConnection->pthis->comm.alias);
	}
	else
	{
	    // connection was lost, reset alias
	    conn_alias[0] = 0;
	    prompt_host.assign (PROMPT_TEXT);
	    pConnection = NULL;
	}
    }

    pCurrConn = pConnection;
    return pCurrConn;
}

int run_client(int argc, char *argv[], sqlite3 * db)
{
    int n;
    int input_rc = 0;
    int message_length = 0;
    int response_length = 0;
    unsigned char *response = NULL;
    unsigned char *client_buffer = NULL;
    int serverret = 0;
    char servermessage[100];
    int rc = 0;
    pcomm_chain pConnection = NULL;
    char hostname[255];
    int portno = 0;
    string prompt_host;
    bool quit = false;
    char conn_alias[255];

    hostname[0] = 0;
    if (argc == 3)
    {
	strcpy (hostname, argv[1]);
	if (isInteger (string (argv[2])))
	{
	    string str_port = string (argv[2]);
	    str_port = trim (str_port);

	    std::string::size_type sz;

	    portno = stoi (str_port, &sz);
	}
	else
	{
	    return -1;
	}
    }
    //    if (connect_to_peer(hostname,portno,&pConnection) == -1)
    //	goto cleanup;

    // Get client_buffer memory    
    if ((client_buffer = (unsigned char *) malloc (CLIENT_BUFFER_SIZE * sizeof (unsigned char))) == NULL)
	goto cleanup;
    memset (client_buffer, 0, MEMSIZE);

    // Get response memory
    if ((response = (unsigned char *) malloc (MEMSIZE * sizeof (unsigned char))) == NULL)
	goto cleanup;
    // clear response memory
    memset (response, 0, MEMSIZE);
    conn_alias[0] = 0;
    servermessage[0] = 0;

    prompt_host.assign (PROMPT_TEXT);
    if (argc >= 3)
    {
	connect_to_peer (hostname, portno, &pConnection);
	string alias = string (pConnection->pthis->comm.hostname);
	alias.append (to_string ((pConnection->pthis->comm.portno)));

	strncpy (pConnection->pthis->comm.alias, alias.c_str (), alias.length ());
	pConnection->pthis->comm.alias[alias.length ()] = '\0';

    }

    // Loop forever sending then receiving messages    
    while (!quit)
    {
	pConnection = purge_and_set_connections (pConnection, conn_alias, prompt_host);

	// Get client input
	if ((rc = get_command_line (client_buffer, &message_length, prompt_host)) != -1)
	{
	    input_rc = process_local_commands (client_buffer, &message_length, &pConnection);

	    if (input_rc == 1) continue;
	    else if (pConnection == NULL)
	    {
		cout << "Remote connection is not set. Connect or switch to existing connection\n";
		continue;
	    }

	    if ((input_rc == 0) && (rc = build_request_message (client_buffer, &message_length, pConnection)) != -1)
	    {// Build request message
		if (message_length > 0)
		{
		    // Send input to peer
		    if (send_message_to_peer (client_buffer, message_length, pConnection) == -1)
			rc = -1;
		    else
		    {
			// wait and get peer response
			if ((response_length = receive_response_from_peer (client_buffer, pConnection)) == -1)
			    return -1;
			else
			{
			    // Process peer response
			    if (process_remote_request (client_buffer, response, &serverret, servermessage, pConnection) == -1)
				rc = -1;
			    else
			    {
				// print peer error message of there was one, otherwise continue the loop
				if (serverret != 0)
				    cout << servermessage << endl;
			    }
			}
		    }
		}
	    }
	}
	else
	{
	    quit = true;
	}
	print_last_error_reset ();
    }

cleanup:
    if (response != NULL)
	free (response);
    if (client_buffer != NULL)
	free (client_buffer);
    return 0;
}
