//not specify pid，specify hypercall
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

reg_t cr3;
//vmi_pid_t pid;
vmi_event_t mm_event;
addr_t vaddr, paddr;

static int interrupted = 0;

void print_event(vmi_event_t *event){
    printf("\tPAGE %"PRIx64" ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %u)\n",
        event->mem_event.physical_address,
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event->mem_event.gfn,
        event->mem_event.offset,
        event->mem_event.gla,
        event->vcpu_id
    );
}

void mm_callback(vmi_instance_t vmi, vmi_event_t *event) {

    print_event(event);

    if(event->mem_event.gla == vaddr) {
        printf("\tCought the original hypercall executing again!");
        vmi_clear_event(vmi, event);
        interrupted = 1;
    } else {
        printf("\tEvent on same page, but not the hypercall");
        vmi_clear_event(vmi, event);

        /* These two calls are equivalent */
        //vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
    }

    printf("\n}\n");
}

int main(int argc, char **argv)
{
        vmi_instance_t vmi = NULL;
        status_t status = VMI_SUCCESS;
        if (argc != 3) {
                printf("Usage: %s <vmname> <vaddr>\n", argv[0]);
                return 1;
        }
        char *name=argv[1];
	char *vaddr_str=argv[2];
        vaddr =(addr_t) strtoul(vaddr_str, NULL, 16);
	//vmi_pid_t pid=atoi(argv[3]);
        if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE) {
                printf("Failed to init LibVMI library.\n");
                return 1;
        }
        printf("success to init LibVMI\n");
	printf("virtual address is:%lx\n",vaddr);
	//printf("pid is: %d\n",pid);
        paddr = vmi_translate_kv2p(vmi,vaddr);
        printf("physical address is::%lx\n",paddr);

	printf("Preparing memory event to catch HYPERCALL at PA 0x%lx, page 0x%lx\n",
            paddr, paddr >> 12);
	vmi_pause_vm(vmi);
	SETUP_MEM_EVENT(&mm_event, paddr, VMI_MEMEVENT_PAGE,
                    VMI_MEMACCESS_RW, mm_callback);
	vmi_resume_vm(vmi);
	while(!interrupted){
        	status = vmi_events_listen(vmi,500);
	        if (status != VMI_SUCCESS) {
        	    printf("Error waiting for events, quitting...\n");
	            interrupted = -1;
		}
        }
	printf("Finished with test.\n");
        vmi_destroy(vmi);
        return 1;
}
