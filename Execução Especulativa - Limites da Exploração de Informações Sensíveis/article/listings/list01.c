uintptr_t vaddr, paddr = 0;
pid = 000;
vaddr = 000;
if (virt_to_phys_user(&paddr, pid, vaddr)) {
	fprintf(stderr, "error: virt_to_phys_user\n");
	return EXIT_FAILURE;
}
//
size_t malicious_x = (size_t) paddr;