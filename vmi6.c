//specify hypercall, add regs output when events happen
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define num 39
reg_t cr3;
//vmi_pid_t pid;
vmi_event_t mm_event[num];
addr_t vaddr[num], paddr[num];
reg_t rax,rbx,rcx,rdx,rsi,rdi;

static int interrupted = 0;

//hypercall table
static const char *hypercall_address[num][2]={
	{"do_set_trap_table","ffff82d08019cab7"},
	{"do_mmu_update","ffff82d08018dc7f"},
	{"do_set_gdt","ffff82d08018b122"},
	{"do_stack_switch","ffff82d08023129e"},
	{"do_set_callbacks","ffff82d0802347d6"},
	{"do_fpu_taskswitch","ffff82d08019bd2e"},
	{"do_sched_op_compat","ffff82d080128090"},
	{"do_platform_op","ffff82d080174b40"},
	{"do_set_debugreg","ffff82d08019d000"},
	{"do_get_debugreg","ffff82d08019d023"},
	{"do_update_descriptor","ffff82d08018ac73"},
	{"do_ni_hypercall","ffff82d0801126ee"},
	{"do_memory_op","ffff82d0801166b7"},
	{"do_multicall","ffff82d0801190f9"},
	{"do_update_va_mapping","ffff82d08018993c"},
	{"do_set_timer_op","ffff82d0801284f0"},
	{"do_event_channel_op_compat","ffff82d08016b700"},
	{"do_xen_version","ffff82d080112130"},
	{"do_console_io","ffff82d08013fbb4"},
	{"do_physdev_op_compat","ffff82d08016b691"},
	{"do_grant_table_op","ffff82d08010e62c"},
	{"do_vm_assist","ffff82d0801126c8"},
	{"do_update_va_mapping_otherdomain","ffff82d0801898d1"},
	{"do_iret","ffff82d08023429c"},
	{"do_vcpu_op","ffff82d080105f41"},
	{"do_set_segment_base","ffff82d080231308"},
	{"do_mmuext_op","ffff82d08018c100"},
	{"do_xsm_op","ffff82d08015917f"},
	{"do_nmi_op","ffff82d08011264c"},
	{"do_sched_op","ffff82d080128134"},
	{"do_callback_op","ffff82d0802346d0"},
	{"do_xenoprof_op","ffff82d08013bbd2"},
	{"do_event_channel_op","ffff82d080107e07"},
	{"do_physdev_op","ffff82d080192794"},
	{"do_hvm_op","ffff82d0801c988e"},
	{"do_sysctl","ffff82d08012aba9"},
	{"do_domctl","ffff82d080102fa9"},
	{"do_kexec_op","ffff82d080114f7c"},
	{"do_tmem_op","ffff82d080136e42"},
};

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

//callback function
void mm_callback(vmi_instance_t vmi, vmi_event_t *event) {

    print_event(event);
    vmi_get_vcpureg(vmi,&rax,RAX,0);
    vmi_get_vcpureg(vmi,&rbx,RBX,0);
    vmi_get_vcpureg(vmi,&rcx,RCX,0);
    vmi_get_vcpureg(vmi,&rdx,RDX,0);
    vmi_get_vcpureg(vmi,&rsi,RSI,0);
    vmi_get_vcpureg(vmi,&rdi,RDI,0);
    printf("HYPERCALL is: %s\n RAX value is: %lx\n RBX value is: %lx\n RCX value is: %lx\n RDX value is: %lx\n RSI value is: %lx\n RDI value is: %lx\n",
	event->mem_event.hypercall,rax,rbx,rcx,rdx,rsi,rdi);

    if(event->mem_event.gla == event->mem_event.gla2) {
        printf("\tCought the original hypercall executing again!");
        vmi_clear_event(vmi, event);
        interrupted = 1;
    } else {
        printf("\tEvent on same page, but not the hypercall: %s",event->mem_event.hypercall);
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
                printf("Usage: %s <vmname> <hypercall-name>\n", argv[0]);
                return 1;
        }
        char *name=argv[1];
	//vmi_pid_t pid=atoi(argv[3]);
        if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE) {
                printf("Failed to init LibVMI library.\n");
                return 1;
        }
        printf("success to init LibVMI\n");
	int i;
	char *hypercall_name=argv[2];
	for (i = 0; i < num; i++) {
		if (strcmp(hypercall_address[i][0],hypercall_name)==0) {
			vmi_pause_vm(vmi);
			char *vaddr_str=hypercall_address[i][1];
		        vaddr[i] =(addr_t) strtoul(vaddr_str, NULL, 16);
			printf("virtual address is:%lx\n",vaddr);
			paddr[i] = vmi_translate_kv2p(vmi,vaddr[i]);
	        	printf("physical address is::%lx\n",paddr[i]);
			mm_event[i].mem_event.gla2 = vaddr[i];//add comparing gla to memory event structure
			mm_event[i].mem_event.hypercall=hypercall_name;
			printf("Preparing memory event to catch HYPERCALL %s at PA 0x%lx, page 0x%lx\n\n",
	        	    hypercall_name, paddr, paddr[i] >> 12);
			SETUP_MEM_EVENT(&mm_event[i], paddr[i], VMI_MEMEVENT_PAGE,
        		            VMI_MEMACCESS_RWX, mm_callback);
			vmi_register_event(vmi,&mm_event[i]);
			vmi_resume_vm(vmi);
			break;
		}
		if (i>=(num-1)){
			printf("no hypercall found, please check the hypercall name!");
			break;
		}
	}
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
