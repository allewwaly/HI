//trap all HVM hypercalls, only listen on execute events.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <pthread.h>

#define num 42

#define ghashtable_foreach(table, i, key, val) \
      g_hash_table_iter_init(&i, table); \
      while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

struct memevent {
  uint8_t tag;//memory event set or not
  uint8_t backup;//backup for the byte where int3 is wrote
  vmi_instance_t vmi;
  vmi_event_t *event;
  addr_t pa;
  char *hypercall;
  //GHashTable *pa_lookup;
}__attribute__ ((packed));

struct hypercall_table{
        char *name;
        addr_t  address;
        int size;
}__attribute__ ((packed));

typedef struct paras{
	GHashTable *traps;
	vmi_instance_t vmi;
	int interrupted;
}paras_t;

static	paras_t clone;

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
        //{"do_physdev_op",0x82d080192794,4503},
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


// This is the callback when an execute or a read event happens
void vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    uint8_t trap = 0xCC;
    addr_t pa;
    printf("entering vmi_reset_trap\n");

    if (event->type == VMI_EVENT_INTERRUPT) {
        pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
        printf("Resetting trap @ 0x%lx.\n", pa);
        vmi_write_8_pa(vmi, pa, &trap);
    } else {
        vmi_register_event(vmi, event);
        reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
        pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
	//^get the physical address where event happens
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
	//iterate the hash table stored in event->data to write back the first byte
        ghashtable_foreach(containers, i, key, s)
        {
            if (pa >= s->pa - 7 && pa <= s->pa + 7) {
                printf("Violation @ 0x%lx. Resetting trap @ 0x%lx.\n", pa, s->pa);
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
}

// This is the callback when an write event happens
void vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
    printf("entering vmi_save_and_reset_trap\n");
    vmi_register_event(vmi, event);
    uint8_t trap = 0xCC;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    GHashTable *containers = event->data;
    GHashTableIter i;
    addr_t *key = NULL;
    struct memevent *s = NULL;
    ghashtable_foreach(containers, i, key, s)
    {
        if (s && s->tag == 1) {//if it's already guarded
            if (pa >= s->pa - 7 && pa <= s->pa + 7) {
                //save the write
                vmi_read_8_pa(vmi, s->pa, &s->backup);//backup the new value of 1st byte
                //add trap back
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
}

void trap_guard(vmi_instance_t vmi, vmi_event_t *event) {
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    vmi_clear_event(vmi, event);
    printf("\nentering trap_guard!\n");
    if (event->mem_event.out_access & VMI_MEMACCESS_X) {
        printf("Exec memaccess @ 0x%lx. Page %lx.\n", pa, event->mem_event.gfn);
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            if (s && s->tag == 1) {
                if (pa >= s->pa - 7 && pa <= s->pa + 7) {//if the event is happen in the same byte with trapped s->pa
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);//recover the original value to ensure the right execution
                }
		else printf("event not happen in the first byte\n");
            }
	    else printf("not guarded address\n");
        }
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    }

    if (event->mem_event.out_access & VMI_MEMACCESS_R) {
        printf("Read memaccess @ 0x%lx. Page %lu.\n", pa, event->mem_event.gfn);
        //read_count++;
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            if (s && s->tag == 1) {
                if (pa >= s->pa - 7 && pa <= s->pa + 7) {
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);//to return the origin value so as to avoid being detected
                }
            }
        }
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
    }

    if (event->mem_event.out_access & VMI_MEMACCESS_W) {
        //write_count++;
        printf("Write memaccess @ 0x%lx. Page %lu.\n", pa,
                event->mem_event.gfn);

        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            if (s && s->tag == 1) {
                if (pa >= s->pa - 7 && pa <= s->pa+7) {
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);
                }
            }
        }
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_save_and_reset_trap);//save the write and reset
    }
}

void int3_cb(vmi_instance_t vmi, vmi_event_t *event){
    printf("entering int3_cb\n");
    addr_t pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
    printf("interrupt event happened at pa 0x%lx\n",pa);
    //vmi_clear_event(vmi, event);

    //we need to distinguish normal int3 interrupt and injected one
    //for normal one (debugger), just reinject
    //for injected one, write back the original value to make it executable

    GHashTable *containers = event->data;
    GHashTableIter i;
    addr_t *key = NULL;
    struct memevent *s = NULL;
    ghashtable_foreach(containers, i, key, s)
    {
        if (pa > s->pa - 7 && pa <= s->pa + 7){
                printf("hypercall %s happend at pa 0x%lx \n",s->hypercall,s->pa);
                vmi_write_8_pa(vmi, s->pa, &s->backup);
                event->interrupt_event.reinject = 0;
                vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_reset_trap);
        }
        else
                event->interrupt_event.reinject = -1;
    }
}

void *interrupt_listen(void *input){
	paras_t *clone=(paras_t *)input;
	clone->interrupted = 0;

        vmi_event_t interrupt_event;
        memset(&interrupt_event, 0, sizeof(vmi_event_t));
        interrupt_event.type = VMI_EVENT_INTERRUPT;
        interrupt_event.interrupt_event.intr = INT3;
        interrupt_event.callback = int3_cb;
	interrupt_event.data=clone->traps;

        if (VMI_SUCCESS!=vmi_register_event(clone->vmi, &interrupt_event)){
                printf("*** FAILED TO REGISTER INTERRUPT EVENT\n");
	        GHashTable *containers = clone->traps;
		GHashTableIter i;
		addr_t *key = NULL;
		struct memevent *s = NULL;
		ghashtable_foreach(containers, i, key, s)
		{
                        free(s);
		}
                clone->interrupted= -1;
        }
        else    printf("success register interrupt event\n");

    vmi_resume_vm(clone->vmi);

    while (!clone->interrupted) {
        printf("Waiting for events ...\n");
        status_t status = vmi_events_listen(clone->vmi, 500);

        if ( VMI_SUCCESS != status ) {
            printf("Error waiting for events or timout, quitting...\n");
            clone->interrupted = -1;
        }
    }

    //vmi_pause_vm(clone->vmi);

    printf("Vmi clone thread exiting\n");
    pthread_exit(0);
    return NULL;
}


void inject_traps(paras_t *clone){
        vmi_instance_t vmi = clone->vmi;
	GHashTable *traps= g_hash_table_new(g_int64_hash, g_int64_equal);
	uint8_t trap=0xCC,byte=0;
	int i;
	vmi_pause_vm(vmi);
	addr_t va,pa;
	reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, 0);//?!vcpu=0

	for (i = 0; i < num; i++) {
		va=hypercalls[i].address;
                pa = vmi_pagetable_lookup(vmi, cr3, va);
		char *hypercall_name=hypercalls[i].name;

        	printf("\n\nTrying to trap HYPERCALL %s @ VA 0x%lx PA 0x%lx PAGE 0x%lx\n", hypercall_name, va, pa, pa >> 12);

		vmi_read_8_pa(vmi, pa, &byte);//read the first byte of the pa
       		if (byte == trap) {
	            printf("** SKIPPING, PA IS ALREADY TRAPPED @ 0x%lx for HYPERCALL %s!\n",
               		    pa, hypercall_name);
	            continue;//break out here might miss inserting record?
	        }

		struct memevent *record = g_malloc0(sizeof(struct memevent));
		record->tag = 1;
		record->pa = pa;
		record->vmi = vmi;
		record->event = vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE);//get the event set on the same page with pa, might be null
		record->backup = byte;
		record->hypercall=hypercall_name;
		if (VMI_FAILURE == vmi_write_8_pa(vmi,pa,&trap)) {//write trap to the first byte
	            printf("FAILED TO INJECT TRAP @ 0x%lx !\n", pa);
	            continue;
	        }

		//save the traps to a hashtable, used in interrupt callback function
                if(g_hash_table_lookup(traps,&record->pa))
                        printf("pa is already trapped\n");
                else{
                        g_hash_table_insert(traps,&record->pa,record);
                        printf("successfully inject traps at pa 0x%lx\n",pa);
                }

	        if(!record->event){//if the memory not being setup events, then set one
			record->event = g_malloc0(sizeof(vmi_event_t));
			record->event->mem_event.hypercall=hypercall_name;//new item hypercall!
			SETUP_MEM_EVENT(record->event, record->pa, VMI_MEMEVENT_PAGE,VMI_MEMACCESS_RW, trap_guard);//setup recall event
			if(VMI_FAILURE==vmi_register_event(vmi,record->event)){//register recall event
				printf("*** FAILED TO REGISTER MEMORY GUARD @ PAGE 0x%lx ***\n", pa >> 12);
				free(record->event);
				free(record);
				continue;
			};
			//create a hash table for every memory event
			record->event->data = g_hash_table_new(g_int64_hash, g_int64_equal);
			printf("New memory event set on page 0x%lx\n", pa >> 12);
		} else {
			printf("Memory event already set on page 0x%lx\n", pa >> 12);
        	}
		printf("trying to insert <pa,memevent> into hashtable\n");
	        struct memevent *test = g_hash_table_lookup(record->event->data, &record->pa);
                if (!test) {
			//insert <pa,record> into data, and data is stored to event
		        g_hash_table_insert(record->event->data, &record->pa, record);
			printf("PA 0x%lx is guarded!\n",pa);
                } else if (test->tag==1) {
                	printf("PA 0x%lx is already guarded\n",pa);
                } else {
      	                printf("PA 0x%lx is trapped by another feature! ERROR/TODO!\n",pa);
       	        }
	}
	clone->traps=traps;
	printf("\nAll %d hypercalls are trapped!\n",num);
}

void close_vmi(paras_t *clone){
	vmi_instance_t vmi = clone->vmi;
	GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(clone->traps, i, key, s)
        {
            vmi_event_t *guard = vmi_get_mem_event(vmi, *key, VMI_MEMEVENT_PAGE);
            if (guard) {
		vmi_write_8_pa(clone->vmi, s->pa, &s->backup);
		free(s);
		vmi_clear_event(vmi, guard);
                g_hash_table_destroy(guard->data);
                free(guard);
	    }
	}
	g_hash_table_destroy(clone->traps);
	if (clone->vmi) {
            vmi_destroy(clone->vmi);
            clone->vmi = NULL;
        }
        printf("close_vmi_clone finished\n");

}

static void close_handler(int sig) {
    clone.interrupted = sig;
}

int main(int argc, char **argv)
{
	/* for a clean exit */
	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

        vmi_instance_t vmi = NULL;
        if (argc != 2) {
                printf("Usage: %s <vmname>\n", argv[0]);
                return 1;
        }
        char *name=argv[1];
        if (vmi_init(&vmi, VMI_AUTO | VMI_INIT_PARTIAL | VMI_INIT_EVENTS, name) == VMI_FAILURE) {//initialize th vmi instance with event enabled
                printf("Failed to init LibVMI library.\n");
                return 1;
        }
        printf("success to init LibVMI\n");
	clone.vmi=vmi;

	inject_traps(&clone);
	/*why should we use pthread? To listen memory event and interrupt event in the same time?
	but memory events are not listened in the callback function! */
	pthread_t clone_thread;
	pthread_create(&clone_thread, NULL, interrupt_listen, (void*) &clone);
        pthread_join(clone_thread, NULL);
	//interrupt_listen(&clone);
        printf("Finished with test.\n");
        close_vmi(&clone);
        return 0;
}
