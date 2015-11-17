//traps+interrupt events
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <signal.h>

#define num 13

#define ghashtable_foreach(table, i, key, val) \
      g_hash_table_iter_init(&i, table); \
      while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

static int interrupted = 0;

struct interevent{
	addr_t pa;
	uint8_t backup;
	char *hypercall;
}__attribute__ ((packed));

struct hypercall_table{
	char *name;
	addr_t  address;
	int size;
}__attribute__ ((packed));

//hypercalls of pv guests from /xen/include/public/xen.h
/*
static struct hypercall_table hypercalls[num]={
        {"do_set_trap_table",0x82d08019cab7,575},
        {"do_mmu_update",0x82d08018dc7f,6238},
        {"do_set_gdt",0x82d08018b122,211},
        {"do_stack_switch",0x82d08023129e,106},
        {"do_set_callbacks",0x82d0802347d6,90},
        {"do_fpu_taskswitch",0x82d08019bd2e,71},
        {"do_sched_op_compat",0x82d080128090,164},
        {"do_platform_op",0x82d080174b40,5938},
        {"do_set_debugreg",0x82d08019d000,35},
        {"do_get_debugreg",0x82d08019d023,118},
        {"do_update_descriptor",0x82d08018ac73,515},
        {"do_ni_hypercall",0x82d0801126ee,13},
        {"do_memory_op",0x82d0801166b7,10818},
        {"do_multicall",0x82d0801190f9,978},
        {"do_update_va_mapping",0x82d08018993c,34},
        {"do_set_timer_op",0x82d0801284f0,220},
        {"do_event_channel_op_compat",0x82d08016b700,111},
        {"do_xen_version",0x82d080112130,1308},
        {"do_console_io",0x82d08013fbb4,1158},
        {"do_physdev_op_compat",0x82d08016b691,111},
        {"do_grant_table_op",0x82d08010e62c,9112},
        {"do_vm_assist",0x82d0801126c8,38},
        {"do_update_va_mapping_otherdomain",0x82d0801898d1,107},
        {"do_iret",0x82d08023429c,430},
        {"do_vcpu_op",0x82d080105f41,1712},
        {"do_set_segment_base",0x82d080231308,222},
        {"do_mmuext_op",0x82d08018c100,7039},
        {"do_xsm_op",0x82d08015917f,19},
        {"do_nmi_op",0x82d08011264c,124},
        {"do_sched_op",0x82d080128134,956},
        {"do_callback_op",0x82d0802346d0,262},
        {"do_xenoprof_op",0x82d08013bbd2,2410},
        {"do_event_channel_op",0x82d080107e07,5449},
        {"do_physdev_op",0x82d080192794,4503},
        {"do_hvm_op",0x82d0801c988e,7720},
        {"do_sysctl",0x82d08012aba9,3796},
        {"do_domctl",0x82d080102fa9,5294},
        {"do_kexec_op",0x82d080114f7c,18},
        {"do_tmem_op",0x82d080136e42,5031},
        {"hvm_memory_op",0x82d0801c6269,98},
        {"hvm_grant_table_op",0x82d0801c6463,73},
        {"hvm_vcpu_op",0x82d0801c62cb,43},
        {"hvm_physdev_op",0x82d0801c63fb,104},
};
*/
//hvm_hypercall64_table from /xen/arch/x86/hvm/hvm.c
static  struct hypercall_table hypercalls[num]={
        {"hvm_memory_op",0xffff82d0801c6269,98},
        {"hvm_grant_table_op",0xffff82d0801c6463,73},
        {"hvm_vcpu_op",0xffff82d0801c62cb,43},
        {"hvm_physdev_op",0xffff82d0801c63fb,104},
        {"do_xen_version",0xffff82d080112130,1308},
        {"do_console_io",0xffff82d08013fbb4,1158},
        {"do_event_channel_op",0xffff82d080107e07,5449},
//        {"do_sched_op",0xffff82d080128134,956}, //uncomment it would cause the guest reboot
        {"do_set_timer_op",0xffff82d0801284f0,220},
        {"do_xsm_op",0xffff82d08015917f,19},
        {"do_hvm_op",0xffff82d0801c988e,7720},
        {"do_sysctl",0xffff82d08012aba9,3796},
        {"do_domctl",0xffff82d080102fa9,5294},
        {"do_tmem_op",0xffff82d080136e42,5031},
};

event_response_t  vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    uint8_t trap = 0xCC;
    addr_t pa;
    printf("entering vmi_reset_trap\n");

    if (event->type == VMI_EVENT_INTERRUPT) {
        pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
        printf("Resetting trap @ 0x%lx.\n", pa);
        vmi_write_8_pa(vmi, pa, &trap);
    }
    return 0;
}

event_response_t  int3_cb(vmi_instance_t vmi, vmi_event_t *event){
    printf("entering int3_cb\n");
    addr_t pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
    printf("interrupt event happened at pa 0x%lx\n",pa);
    GHashTable *containers = event->data;
    GHashTableIter i;
    addr_t *key = NULL;
    struct interevent *s = NULL;
    ghashtable_foreach(containers, i, key, s)
    {
	if (pa > s->pa - 7 && pa <= s->pa + 7){
		printf("hypercall %s happend at pa 0x%lx \n",s->hypercall,s->pa);
                vmi_write_8_pa(vmi, s->pa, &s->backup);
                event->interrupt_event.reinject = 0;
                vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
		return 1;
	}
//	else
    }
    event->interrupt_event.reinject = 1;
    return 0;
}

static void close_handler(int sig){
    interrupted = sig;
}

int main(int argc, char **argv)
{
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);
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

	GHashTable *traps= g_hash_table_new(g_int64_hash, g_int64_equal);
	int i;
	vmi_pause_vm(vmi);

	struct interevent *records[num];
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

                if (g_hash_table_lookup(traps, &pa))
                    continue;

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
		records[i] = g_malloc0(sizeof(struct interevent));
		records[i]->pa=pa;
		records[i]->backup=byte;
		records[i]->hypercall=hypercall_name;
		g_hash_table_insert(traps,&records[i]->pa,records[i]);
		printf("successfully inject traps at pa 0x%lx\n",pa);
	}
	printf("\nAll %d hypercalls are trapped!\n",num);

        vmi_event_t interrupt_event;
        memset(&interrupt_event, 0, sizeof(vmi_event_t));
        interrupt_event.type = VMI_EVENT_INTERRUPT;
        interrupt_event.interrupt_event.intr = INT3;
        interrupt_event.callback = int3_cb;
        interrupt_event.data = traps;//

	if (VMI_SUCCESS!=vmi_register_event(vmi, &interrupt_event)){
		printf("*** FAILED TO REGISTER INTERRUPT EVENT\n");
		interrupted= -1;
	}
	else	printf("success register interrupt event\n");

	vmi_resume_vm(vmi);

	while(!interrupted){
		printf("Waiting for events...\n");
        	status = vmi_events_listen(vmi,500);
	        if (status != VMI_SUCCESS) {
        	    printf("Error waiting for events, quitting...\n");
	            interrupted = -1;
		}
        }
	printf("Finished with test.\n");


        GHashTableIter j;
        addr_t *key = NULL;
        struct interevent *s = NULL;
        ghashtable_foreach(traps, j, key, s){
		if(s){
			vmi_write_8_pa(vmi, s->pa, &s->backup);
			free(s);
		}
	}
	vmi_clear_event(vmi,&interrupt_event);
	g_hash_table_destroy(traps);
        vmi_destroy(vmi);
        return 1;
}
