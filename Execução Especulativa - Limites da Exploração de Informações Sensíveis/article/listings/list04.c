//
// Adapted by rios0rios0 on 08/03/19.
//

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512];
char *secret = "The Magic Words are Squeamish Ossifrage.";
uint8_t temp = 0;

void victim_function(size_t x) {
	if (x < array1_size) {
		temp &= array2[array1[x] * 512];
	}
}

int main(int argc, char **argv) {
	if (argc > 1) {
		int input_index = (*argv[1] - '0');
		victim_function(input_index);
	} else {
		printf("pid %ju\n", (uintmax_t) getpid());
		printf("vaddr of array1 %p\n", (void *) array1);
		printf("vaddr of secret %p\n", (void *) secret);
	}
}