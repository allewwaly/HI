//memory execute events + inject traps
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <signal.h>

#define num 43

#define ghashtable_foreach(table, i, key, val) \
      g_hash_table_iter_init(&i, table); \
      while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

static int interrupted = 0;

struct memevent{
	addr_t pa;
	uint8_t backup;
	char *hypercall;
	vmi_event_t *event;
}__attribute__ ((packed));

struct hypercall_table{
	char *name;
	addr_t  address;
	int size;
}__attribute__ ((packed));

static struct hypercall_table hypercalls[num]={
        {"do_set_trap_table",0xffff82d08019cab7,575},
        {"do_mmu_update",0xffff82d08018dc7f,6238},
        {"do_set_gdt",0xffff82d08018b122,211},
        {"do_stack_switch",0xffff82d08023129e,106},
        {"do_set_callbacks",0xffff82d0802347d6,90},
        {"do_fpu_taskswitch",0xffff82d08019bd2e,71},
        {"do_sched_op_compat",0xffff82d080128090,164},
        {"do_platform_op",0xffff82d080174b40,5938},
        {"do_set_debugreg",0xffff82d08019d000,35},
        {"do_get_debugreg",0xffff82d08019d023,118},
        {"do_update_descriptor",0xffff82d08018ac73,515},
        {"do_ni_hypercall",0xffff82d0801126ee,13},
        {"do_memory_op",0xffff82d0801166b7,10818},
        {"do_multicall",0xffff82d0801190f9,978},
        {"do_update_va_mapping",0xffff82d08018993c,34},
        {"do_set_timer_op",0xffff82d0801284f0,220},
        {"do_event_channel_op_compat",0xffff82d08016b700,111},
        {"do_xen_version",0xffff82d080112130,1308},
        {"do_console_io",0xffff82d08013fbb4,1158},
        {"do_physdev_op_compat",0xffff82d08016b691,111},
        {"do_grant_table_op",0xffff82d08010e62c,9112},
        {"do_vm_assist",0xffff82d0801126c8,38},
        {"do_update_va_mapping_otherdomain",0xffff82d0801898d1,107},
        {"do_iret",0xffff82d08023429c,430},
        {"do_vcpu_op",0xffff82d080105f41,1712},
        {"do_set_segment_base",0xffff82d080231308,222},
        {"do_mmuext_op",0xffff82d08018c100,7039},
        {"do_xsm_op",0xffff82d08015917f,19},
        {"do_nmi_op",0xffff82d08011264c,124},
        {"do_sched_op",0xffff82d080128134,956},
        {"do_callback_op",0xffff82d0802346d0,262},
        {"do_xenoprof_op",0xffff82d08013bbd2,2410},
        {"do_event_channel_op",0xffff82d080107e07,5449},
        {"do_physdev_op",0xffff82d080192794,4503},
        {"do_hvm_op",0xffff82d0801c988e,7720},
        {"do_sysctl",0xffff82d08012aba9,3796},
        {"do_domctl",0xffff82d080102fa9,5294},
        {"do_kexec_op",0xffff82d080114f7c,18},
        {"do_tmem_op",0xffff82d080136e42,5031},
        {"hvm_memory_op",0xffff82d0801c6269,98},
        {"hvm_grant_table_op",0xffff82d0801c6463,73},
        {"hvm_vcpu_op",0xffff82d0801c62cb,43},
        {"hvm_physdev_op",0xffff82d0801c63fb,104},
};

void vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    uint8_t trap = 0xCC;
    addr_t pa;
    printf("entering vmi_reset_trap\n");

    if (event->type == VMI_EVENT_INTERRUPT) {
        pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
        printf("Resetting trap @ 0x%lx.\n", pa);
        vmi_write_8_pa(vmi, pa, &trap);
    }else {

        vmi_register_event(vmi, event);
        reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        pa = (event->mem_event.gfn << 12) + event->mem_event.offset;

        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s)
        {
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                printf("Violation @ 0x%lx. Resetting trap @ 0x%lx.\n", pa, s->pa);
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
}

void int3_cb(vmi_instance_t vmi, vmi_event_t *event){
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    printf("memory event happened at pa 0x%lx of hypercall %s vcpu %x\n",pa,event->mem_event.hypercall,event->vcpu_id);
    vmi_clear_event(vmi, event);

    //we need to distinguish normal int3 interrupt and injected one
    //for normal one (debugger), just reinject
    //for injected one, write back the original value to make it executable
    if (event->mem_event.out_access & VMI_MEMACCESS_X) {
 	    printf("X event happened\n");
	    GHashTable *containers = event->data;
	    GHashTableIter i;
	    addr_t *key = NULL;
	    struct memevent *s = NULL;
	    ghashtable_foreach(containers, i, key, s)//why write every byte back? shouldn't it only write back the byte where X event happens?
	    {
		if(s){
		    if (pa > s->pa - 7 && pa <= s->pa + 7){
        	        printf("** Mem event removing trap 0x%lx\n", s->pa);
 	                vmi_write_8_pa(vmi, s->pa, &s->backup);//recover the original value
 		    }
		}
		else printf("not guarded address\n");
	    }
	    vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    }
}


int main(int argc, char **argv)
{
	addr_t va, pa;
        vmi_instance_t vmi = NULL;
        status_t status = VMI_SUCCESS;
	uint8_t trap=0xCC,byte=0;
        if (argc != 2) {
                printf("Usage: %s <vmname>\n", argv[0]);
                return 1;
        }
        char *name=argv[1];
	//vmi_pid_t pid=atoi(argv[3]);how to init a vmi for hypervisor?
        if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_PARTIAL | VMI_INIT_EVENTS, name) == VMI_FAILURE) {//initialize th vmi instance with event enabled
                printf("Failed to init LibVMI library.\n");
                return 1;
         }
        printf("success to init LibVMI\n");

	int i;
	vmi_pause_vm(vmi);
	//inject int3 to every hypercall handler
	for (i = 0; i < num; i++) {
		va=hypercalls[i].address;
		char *hypercall_name=hypercalls[i].name;
		//obtain pa using CR3 instead
		reg_t cr3;
		vmi_get_vcpureg(vmi, &cr3, CR3, 0);
		pa = vmi_pagetable_lookup(vmi, cr3, va);
		//pa = vmi_translate_kv2p(vmi,va);
		if (!pa){
		    printf("failed to obtain pa of hypercall %s\n",hypercall_name);
		    continue;
		}

        	printf("\n\nTrying to trap HYPERCALL %s @ VA 0x%lx PA 0x%lx PAGE 0x%lx\n", hypercall_name, va, pa, pa >> 12);

		vmi_read_8_pa(vmi, pa, &byte);//read the first byte of the pa
       		if (byte == trap) {
	            printf("** SKIPPING, PA IS ALREADY TRAPPED @ 0x%lx for HYPERCALL %s!\n",
               		    pa, hypercall_name);
	            continue;
	        }
		if (VMI_FAILURE == vmi_write_8_pa(vmi,pa,&trap)) {//write trap to the first byte
	            printf("FAILED TO INJECT TRAP @ 0x%lx !\n", pa);
	            continue;
	        }
		struct memevent *record = g_malloc0(sizeof(struct memevent));
		record->pa=pa;
		record->backup=byte;
		record->hypercall=hypercall_name;
		record->event= vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE);

		if(!record->event){
			record->event=g_malloc0(sizeof(vmi_event_t));
	                record->event->data = g_hash_table_new(g_int64_hash, g_int64_equal);
			record->event->mem_event.hypercall=hypercall_name;
			SETUP_MEM_EVENT(record->event, record->pa, VMI_MEMEVENT_PAGE,VMI_MEMACCESS_X, int3_cb);
                        if(VMI_FAILURE==vmi_register_event(vmi,record->event)){//register recall $
                                printf("*** FAILED TO REGISTER MEMORY GUARD @ PAGE 0x%lx ***\n", pa>>12);
                                free(record->event);
                                free(record);
                                continue;
                        }
                        printf("New memory event trap set on page 0x%lx\n", pa >> 12);
		} else {
                        printf("Memory event trap already set on page 0x%lx\n", pa >> 12);
                }

		if(g_hash_table_lookup(record->event->data,&record->pa))
			printf("pa 0x%lx is already guarded\n",pa);
		else{
			g_hash_table_insert(record->event->data,&record->pa,record);
			printf("pa 0x%lx is being guarded\n",pa);
		}
	}
	printf("\nAll %d hypercalls are trapped and guarded!\n",num);

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
