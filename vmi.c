#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
int main(int argc, char **argv)
{
	vmi_instance_t vmi;
        if (argc != 3) {
        	printf("Usage: %s <vmname> <vaddr>\n", argv[0]);
	        return 1;
        }
	char *name=argv[1];
	char *vaddr_str=argv[2];
        addr_t vaddr =(addr_t) strtoul(vaddr_str, NULL, 16);
        if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE, name) == VMI_FAILURE) {
        	printf("Failed to init LibVMI library.\n");
	        return 1;
        }
	printf("success to init LibVMI\n");
	addr_t paddr = vmi_translate_kv2p(vmi,vaddr);
	printf("paddr is::%lx\n",paddr);
	vmi_destroy(vmi);
	return 1;
}
