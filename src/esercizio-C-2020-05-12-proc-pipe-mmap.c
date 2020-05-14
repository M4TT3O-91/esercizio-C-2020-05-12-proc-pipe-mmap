/*
 * esercizio-C-2020-05-12-proc-pipe-mmap.c
 * il processo padre per comunicare con il processo figlio prepara:
 *- una pipe
 *- una memory map condivisa
 *
 *il processo padre manda i dati al processo figlio attraverso la pipe
 *
 *il processo figlio restituisce il risultato attraverso la memory map convidisa
 *
 *il processo padre prende come argomento a linea di comando un nome di file.
 *il processo padre legge il file e manda i contenuti attraverso la pipe al processo figlio.
 *
 *il processo figlio riceve attraverso la pipe i contenuti del file e calcola SHA3_512.
 *
 *quando la pipe raggiunge EOF, il processo figlio produce il digest di SHA3_512 e lo scrive nella
 *memory map condivisa, poi il processo figlio termina.
 *
 *quando al processo padre viene notificato che il processo figlio ha terminato,
 *prende il digest dalla memory map condivisa e lo scrive a video
 *("SHA3_512 del file %s è il seguente: " <segue digest in formato esadecimale>).
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <errno.h>

#include <openssl/evp.h>


#define FILE_SIZE 1024*1024*16
#define HANDLE_ERROR(msg) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE); }
#define HANDLE_ERROR2(msg, mdctx) { fprintf(stderr, "%s\n", msg); EVP_MD_CTX_destroy(mdctx); exit(EXIT_FAILURE); }
#define CHECK_ERR(a,msg) {if ((a) == -1) { perror((msg)); exit(EXIT_FAILURE); } }

__off_t get_file_size(char *file_name);
__off_t get_fd_size(int fd);
unsigned char* sha3_512(char *addr, unsigned int size, int *result_len_ptr);

int main(int argc, char *argv[]) {

	//char *file_name;
	char *file_name = "/home/matteo/prova.txt";

//	if (argc > 1) {
//		file_name = strcat(file_name, argv[1]);
//	} else {
//		file_name = strcat(file_name, "prova.txt");
//	}

	int fd = open(file_name,
	O_RDONLY,
	S_IRUSR | S_IWUSR // l'utente proprietario del file avrà i permessi di lettura e scrittura sul nuovo file
	);

	unsigned long file_size = get_fd_size(fd);

	CHECK_ERR(fd, "open()")

	//Preparo la pipe
	int pipe_fd[2];
	int res;

	if (pipe(pipe_fd) == -1) {
		perror("pipe()");

		exit(EXIT_FAILURE);
	}

	//creare mmap
	char *addr;

	addr = mmap(NULL, // NULL: è il kernel a scegliere l'indirizzo
			file_size, // dimensione della memory map
			PROT_READ | PROT_WRITE, // memory map leggibile e scrivibile
			MAP_SHARED, // memory map condivisibile con altri processi
			fd, 0);

	switch (fork()) {
	case -1:
		perror("problema con fork");
		exit(EXIT_FAILURE);

	case 0: // processo FIGLIO: legge dalla PIPE
		printf("[child] starting\n");
		close(pipe_fd[1]); // chiudiamo l'estremità di scrittura della pipe

		char *child_buffer = malloc(file_size);
		if (child_buffer == NULL) {
			perror("malloc()");
			exit(EXIT_FAILURE);
		}

		// pipe vuota: read() si blocca in attesa di dati
		while ((res = read(pipe_fd[0], child_buffer, file_size)) > 0) {
			printf("[child] read %d byte from pipe\n", res);


		}

		if (res == -1) {
			perror("read()");
		}

		printf("[child] bye\n");
		close(pipe_fd[0]);
		exit(EXIT_SUCCESS);

	default: // processo PADRE: scrive nella PIPE

		printf("[parent] starting\n");
		close(pipe_fd[0]); // chiudiamo l'estremità di lettura della pipe
		char *parent_buffer = malloc(file_size);

		if (parent_buffer == NULL) {
			perror("malloc()");
			exit(EXIT_FAILURE);
		}

		// leggo dal file e salvo in buffer...
		while (read(fd, parent_buffer, file_size) > 0)
			// se pipe piena (capacità: 16 pages) allora write() si blocca
			res = write(pipe_fd[1], parent_buffer, file_size);

		CHECK_ERR(res, "write()")

		printf("[parent] %d bytes written to pipe\n", res);

		close(pipe_fd[1]); // chiudiamo estremità di scrittura della pipe
		// dall'altra parte verrà segnalato EOF
//		printf("[parent] before wait()\n");
		wait(NULL);
		printf("[parent] bye\n");
		free(parent_buffer);
		exit(EXIT_SUCCESS);
	}

	return EXIT_SUCCESS;

}

__off_t get_file_size(char *file_name) {

	struct stat sb;
	int res;

	res = stat(file_name, &sb);

	if (res == -1) {
		perror("stat()");
		return -1;
	}

	return sb.st_size;
}

__off_t get_fd_size(int fd) {

	struct stat sb;
	int res;
	res = fstat(fd, &sb);
	if (res == -1) {
		perror("fstat()");
		return -1;
	}
	// printf("File size: %lld bytes\n", (long long) sb.st_size);
	//printf("sizeof(__off_t) = %lu\n", sizeof(__off_t));
	return sb.st_size;
}

unsigned char * sha3_512(char * addr, unsigned int size, int * result_len_ptr) {

	EVP_MD_CTX * mdctx;
	int val;
	unsigned char * digest;
	unsigned int digest_len;
	EVP_MD * algo = NULL;

	algo = EVP_sha3_512();

	if ((mdctx = EVP_MD_CTX_create()) == NULL) {
		HANDLE_ERROR("EVP_MD_CTX_create() error")
	}

	// initialize digest engine
	if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestInit_ex() error", mdctx)
	}

	// provide data to digest engine
	if (EVP_DigestUpdate(mdctx, addr, size) != 1) { // returns 1 if successful
		HANDLE_ERROR2("EVP_DigestUpdate() error", mdctx)
	}

	digest_len = EVP_MD_size(algo); // sha3_512 returns a 512 bit hash

	if ((digest = (unsigned char *)OPENSSL_malloc(digest_len)) == NULL) {
		HANDLE_ERROR2("OPENSSL_malloc() error", mdctx)
	}

	// produce digest
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) { // returns 1 if successful
		OPENSSL_free(digest);
		HANDLE_ERROR2("EVP_DigestFinal_ex() error", mdctx)
	}

	char * result = malloc(digest_len);
	if (result == NULL) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}

	memcpy(result, digest, digest_len);

	*result_len_ptr = digest_len;

	OPENSSL_free(digest);
	EVP_MD_CTX_destroy(mdctx);

	return result;
}
