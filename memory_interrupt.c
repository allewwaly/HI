//trap all HVM hypercalls, only listen on execute events.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <pthread.h>
#include <xenctrl.h>

#define num 12

#define ghashtable_foreach(table, i, key, val) \
      g_hash_table_iter_init(&i, table); \
      while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

struct memevent {
  int i;//index of hypercall
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

/*static struct hypercall_table hypercalls[num]={
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
};*/

static  struct hypercall_table hypercalls[num]={
        {"hvm_memory_op",0xffff82d0801c6269,98},
        {"hvm_grant_table_op",0xffff82d0801c6463,73},
        {"hvm_vcpu_op",0xffff82d0801c62cb,43},
        {"hvm_physdev_op",0xffff82d0801c63fb,104},
        {"do_xen_version",0xffff82d080112130,1308},
        {"do_console_io",0xffff82d08013fbb4,1158},
        {"do_event_channel_op",0xffff82d080107e07,5449},
        //{"do_sched_op",0xffff82d080128134,956},
        //{"do_set_timer_op",0xffff82d0801284f0,220},
        {"do_xsm_op",0xffff82d08015917f,19},
        {"do_hvm_op",0xffff82d0801c988e,7720},
        {"do_sysctl",0xffff82d08012aba9,3796},
        {"do_domctl",0xffff82d080102fa9,5294},
        {"do_tmem_op",0xffff82d080136e4,5031},
};



// This is the callback when an execute or a read event happens
event_response_t vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

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
	printf("memory read event happens\n");
	//^get the physical address where event happens
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
	//iterate the hash table stored in event->data to write back the first byte
        ghashtable_foreach(containers, i, key, s)
        {
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                printf("Violation @ 0x%lx. Resetting trap @ 0x%lx.\n", pa, s->pa);
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
    return 0;
}

// This is the callback when an write event happens
event_response_t vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {
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
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                //save the write
                vmi_read_8_pa(vmi, s->pa, &s->backup);//backup the new value of 1st byte
                //add trap back
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
    return 0;
}

event_response_t trap_guard(vmi_instance_t vmi, vmi_event_t *event) {
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
                if (pa > s->pa - 7 && pa <= s->pa + 7) {//if the event is happen in the same byte with trapped s->pa
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
        printf("Read memaccess @ 0x%lx. Page %lx.\n", pa, event->mem_event.gfn);
        //read_count++;
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            if (s && s->tag == 1) {
		printf("the potential hypercall number is :%d hypercall is %s\n",s->i,s->hypercall);
                if (pa > s->pa - 7 && pa <= s->pa + 7) {
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);//to return the origin value so as to avoid being detected
                }else
		printf("memory events not in the first byte\n");
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
                if (pa > s->pa - 7 && pa <= s->pa+7) {
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);
                }
            }
        }
        vmi_step_event(vmi, event, event->vcpu_id, 1, vmi_save_and_reset_trap);//save the write and reset
    }
    return 0;
}

//the next instruction is executed after the return of int3_cb, so how should we write the backup?
event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event){
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
		return 1;
        }
//        else
    }
    event->interrupt_event.reinject = 1;
    return 0;
}

void inject_traps(paras_t *clone){
	//paras_t *clone=(paras_t *)input;
        vmi_instance_t vmi = clone->vmi;
	uint8_t trap=0xCC,byte=0;
        uint64_t trapped = 0;
	int i=0;

	vmi_pause_vm(vmi);
	reg_t cr3;
        vmi_get_vcpureg(vmi, &cr3, CR3, 0);//TODO ?!vcpu=0
	//traps= g_hash_table_new(g_int64_hash, g_int64_equal);

	for (; i < num; i++) {
		addr_t va=hypercalls[i].address;
                addr_t pa=vmi_pagetable_lookup(vmi, cr3, va);

	        if (!pa)
        	    continue;

	        if (g_hash_table_lookup(clone->traps, &pa))
        	    continue;

		char *hypercall_name=hypercalls[i].name;

        	printf("\n\nTrying to trap HYPERCALL %s @ VA 0x%lx PA 0x%lx PAGE 0x%lx\n", hypercall_name, va, pa, pa >> 12);

		vmi_read_8_pa(vmi, pa, &byte);//read the first byte of the pa
       		if (byte == trap) {
	            printf("** SKIPPING, PA IS ALREADY TRAPPED @ 0x%lx for HYPERCALL %s!\n",
               		    pa, hypercall_name);
	            continue;//break out here might miss inserting record?
	        }

		struct memevent *record = g_malloc0(sizeof(struct memevent));
		record->i=i;
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

	        if(!record->event){//if the memory not being setup events, then set one
			record->event = g_malloc0(sizeof(vmi_event_t));
			//record->event->mem_event.hypercall=hypercall_name;//new item hypercall!
			SETUP_MEM_EVENT(record->event, record->pa, VMI_MEMEVENT_PAGE,VMI_MEMACCESS_RW, trap_guard);//setup recall event
			if(VMI_FAILURE==vmi_register_event(vmi,record->event)){//register recall event
				printf("*** FAILED TO REGISTER MEMORY GUARD @ PAGE 0x%lx ***\n", pa >> 12);
				free(record->event);
				free(record);
				continue;
			};
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
			printf("PA 0x%lx of HYPERCALL %s is inserted!\n",record->pa,record->hypercall);
                } else if (test->tag==1) {
                	printf("PA 0x%lx is already guarded\n",pa);
                } else {
      	                printf("PA 0x%lx is trapped by another feature! ERROR/TODO!\n",pa);
       	        }

	        g_hash_table_insert(clone->traps, g_memdup(&record->pa, 8), record);

	        trapped++;
        	printf(
                	"Trap added @ VA 0x%lx PA 0x%lx Page %lu for %s! Backup: 0x%x.\n",
	                va, record->pa,
        	        pa >> 12,
                	record->hypercall,
	                record->backup);

	}
	printf("\tInjected %lu traps\n", trapped);
	//clone->traps=traps;
	//printf("\nAll %d hypercalls are trapped!\n",num);
	//print all the traps
        GHashTable *containers = clone->traps;
        GHashTableIter j;
        addr_t *key = NULL;
        struct memevent *s = NULL;
	//char *s = NULL;
	printf("index\tbackup\ttag\thypercall\n");

        ghashtable_foreach(containers, j, key, s)
	{
                printf("%d\t%d\t%d\t%s\n",s->i,s->backup,s->tag,s->hypercall);
		//printf("%s\n", s);
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
                clone->interrupted= -1;
        }
        else    printf("\nsuccess register interrupt event\n");

	vmi_resume_vm(clone->vmi);

	while (!clone->interrupted) {
        	printf("Waiting for interrupt events ...\n");
	        status_t status = vmi_events_listen(clone->vmi, 500);
	        if ( VMI_SUCCESS != status ) {
        	    printf("Error waiting for interrupt events or timout, quitting...\n");
	            clone->interrupted = -1;
        	}
	    }

//	vmi_pause_vm(clone->vmi);

	printf("Vmi clone thread exiting\n");
	pthread_exit(0);
	return NULL;
}

void *memory_listen(void *input){
        paras_t *clone=(paras_t *)input;
        clone->interrupted = 0;
        vmi_resume_vm(clone->vmi);

	while (!clone->interrupted) {
        	printf("Waiting for memory events ...\n");
	        status_t status = vmi_events_listen(clone->vmi, 500);
        	if ( VMI_SUCCESS != status ) {
	            printf("Error waiting for memory events or timout, quitting...\n");
        	    clone->interrupted = -1;
	        }
	}
	printf("finish memory listen thread\n");
	pthread_exit(0);
	return NULL;
}

void close_vmi(paras_t *clone){
	vmi_instance_t vmi = clone->vmi;
    do{
	GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(clone->traps, i, key, s)
        {
            vmi_event_t *guard = vmi_get_mem_event(vmi, *key, VMI_MEMEVENT_PAGE);
            if (guard) {
                GHashTableIter i2;
                addr_t *key2 = NULL;
                struct memevent *container = NULL;
                ghashtable_foreach(guard->data, i2, key2, container) {
                    if (container->tag == 1) {
                        vmi_write_8_pa(clone->vmi, container->pa,
                                &container->backup);
                        free(container);
                    }
                }
		//vmi_write_8_pa(clone->vmi, s->pa, &s->backup);
		//free(s);
		vmi_clear_event(vmi, guard);
                g_hash_table_destroy(guard->data);
                free(guard);
	    }
	}
    }while(0);
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

        //vmi_instance_t vmi = NULL;
        if (argc != 2) {
                printf("Usage: %s <vmname>\n", argv[0]);
                return 1;
        }
        char *name=argv[1];
        if (vmi_init(&clone.vmi, VMI_AUTO | VMI_INIT_PARTIAL | VMI_INIT_EVENTS, name) == VMI_FAILURE) {//initialize th vmi instance with event enabled
                printf("Failed to init LibVMI library.\n");
        	if (clone.vmi != NULL) {
	            vmi_destroy(clone.vmi);
        	}
	        clone.vmi = NULL;
                return 1;
        }
        printf("success to init LibVMI\n");
	//clone.vmi=vmi;
	clone.traps = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, NULL);
	inject_traps(&clone);
	/*why should we use pthread? To listen memory event and interrupt event in the same time?
	but memory events are not listened in the callback function! */
	pthread_t interrupt_thread;//memory_thread;
	pthread_create(&interrupt_thread, NULL, interrupt_listen, (void*) &clone);
        pthread_join(interrupt_thread, NULL);
//	interrupt_listen(&clone);
        printf("Finished with test.\n");
        close_vmi(&clone);
        return 0;
}
