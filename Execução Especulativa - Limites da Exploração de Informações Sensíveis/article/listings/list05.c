#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char *secret = NULL;

int main(int argc, const char **argv) {
    long val = 3072000 + (random() % 1000000);
    void *new_ptr = realloc(secret, val * sizeof(*secret));
    secret = new_ptr;
    for (int i = 0; i < val; i++) {
    	secret[i] = 'A' + (random() % 26);
    }
    time_t begin = time(NULL);
    /* restante do exploit */
    time_t end = time(NULL);
    printf("Time elapsed is %ld seconds.", (end - begin));
    return 0;
}