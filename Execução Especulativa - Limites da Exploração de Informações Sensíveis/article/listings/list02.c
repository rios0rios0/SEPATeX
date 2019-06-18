//
// Created by rios0rios0 on 08/03/19.
//

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

//The secret information on code (it's not matter)
char *secret_info = "Secret information on code.";

int main(int argc, char **argv) {
	while (true) {
		printf("vaddr %p\n", (void *) secret_info);
		printf("pid %ju\n", (uintmax_t) getpid());
		sleep(1);
	}
}