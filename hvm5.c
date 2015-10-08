//only trap all HVM hypercalls, not call callback functions
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>

#define num 12

#define ghashtable_foreach(table, i, key, val) \
      g_hash_table_iter_init(&i, table); \
      while(g_hash_table_iter_next(&i,(void**)&key,(void**)&val))

reg_t cr3;
//vmi_pid_t pid;
vmi_event_t mm_event[num];
addr_t va, pa;
reg_t rax,rbx,rcx,rdx,rsi,rdi;

static int interrupted = 0;

struct memevent {
  uint8_t tag;
  uint8_t backup;
  vmi_instance_t vmi;
  vmi_event_t *event;
  addr_t pa;
  //GHashTable *pa_lookup;
}__attribute__ ((packed));

//hypercall table
static const char *hypercall_address[num][2]={
        {"hvm_memory_op","ffff82d0801c6269"},
        {"hvm_grant_table_op","ffff82d0801c6463"},
        {"hvm_vcpu_op","ffff82d0801c62cb"},
        {"hvm_physdev_op","ffff82d0801c63fb"},
        {"do_xen_version","ffff82d080112130"},
        {"do_console_io","ffff82d08013fbb4"},
        {"do_event_channel_op","ffff82d080107e07"},
        //{"do_sched_op","ffff82d080128134"},
        {"do_set_timer_op","ffff82d0801284f0"},
        {"do_xsm_op","ffff82d08015917f"},
        {"do_hvm_op","ffff82d0801c988e"},
        //{"do_sysctl","ffff82d08012aba9"},
        {"do_domctl","ffff82d080102fa9"},
        {"do_tmem_op","ffff82d080136e4"},
};


// This is the callback when an int3 or a read event happens
void vmi_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    uint8_t trap = 0xCC;
    addr_t pa;

    if (event->type == VMI_EVENT_INTERRUPT) {
        pa = (event->interrupt_event.gfn << 12) + event->interrupt_event.offset;
        //printf("Resetting trap @ 0x%lx.\n", pa);
        vmi_write_8_pa(vmi, pa, &trap);
    } else {
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
                //printf("Violation @ 0x%lx. Resetting trap @ 0x%lx.\n", pa, s->pa);
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
}

// This is the callback when an write event happens
void vmi_save_and_reset_trap(vmi_instance_t vmi, vmi_event_t *event) {

    vmi_register_event(vmi, event);
    uint8_t trap = 0xCC;
    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    GHashTable *containers = event->data;
    GHashTableIter i;
    addr_t *key = NULL;
    struct memevent *s = NULL;
    ghashtable_foreach(containers, i, key, s)
    {
        if (s && s->tag == 1) {
            if (pa > s->pa - 7 && pa <= s->pa + 7) {
                //save the write
                vmi_read_8_pa(vmi, s->pa, &s->backup);
                //add trap back
                vmi_write_8_pa(vmi, s->pa, &trap);
            }
        }
    }
}

void trap_guard(vmi_instance_t vmi, vmi_event_t *event) {

    reg_t cr3;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

    addr_t pa = (event->mem_event.gfn << 12) + event->mem_event.offset;
    vmi_clear_event(vmi, event);

    if (event->mem_event.out_access & VMI_MEMACCESS_R) {
        //printf("Read memaccess @ 0x%lx. Page %lx.\n", pa, event->mem_event.gfn);
        //read_count++;
        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            if (s && s->tag == 1) {
                if (pa > s->pa - 7 && pa <= s->pa + 7) {
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);
                }
            }
        }
        vmi_step_event(vmi, event, 1, 1, vmi_reset_trap);
    }

    if (event->mem_event.out_access & VMI_MEMACCESS_W) {
        //write_count++;
        printf("Write memaccess @ 0x%lu. Page %lu.\n", pa,
                event->mem_event.gfn);

        GHashTable *containers = event->data;
        GHashTableIter i;
        addr_t *key = NULL;
        struct memevent *s = NULL;
        ghashtable_foreach(containers, i, key, s) {
            /*printf("Write memaccess @ 0x%lx. Page %lu. Symbol: %s!%s\n", pa,
                    event->mem_event.gfn, s->symbol.config->name,
                    s->symbol.symbol->name);*/
            if (s && s->tag == 1) {
                if (pa > s->pa - 7 && pa <= s->pa) {
                    printf("** Mem event removing trap 0x%lx\n", s->pa);
                    vmi_write_8_pa(vmi, s->pa, &s->backup);
                }
            }
        }

        vmi_step_event(vmi, event, 1, 1, vmi_save_and_reset_trap);//
    }
}


int main(int argc, char **argv)
{
        vmi_instance_t vmi = NULL;
        status_t status = VMI_SUCCESS;
	uint8_t trap=0xCC,byte=0;

        if (argc != 2) {
                printf("Usage: %s <vmname>\n", argv[0]);
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
	//vmi_pause_vm(vmi);
	for (i = 0; i < num; i++) {
		char *va_str=hypercall_address[i][1];
		char *hypercall_name=hypercall_address[i][0];
	        va =(addr_t) strtoul(va_str, NULL, 16);
		pa = vmi_translate_kv2p(vmi,va);
        	printf("\n\nTrying to trap HYPERCALL %s @ VA 0x%lx PA 0x%lx PAGE 0x%lx\n", hypercall_name, va, pa, pa >> 12);

		vmi_read_8_pa(vmi, pa, &byte);
       		if (byte == trap) {
	            printf("** SKIPPING, PA IS ALREADY TRAPPED @ 0x%lx for HYPERCALL %s!\n",
               		    pa, hypercall_name);
	            continue;
	        }

		struct memevent *record = g_malloc0(sizeof(struct memevent));
		record->tag = 1;
		record->pa = pa;
		record->vmi = vmi;
		record->event = vmi_get_mem_event(vmi, pa, VMI_MEMEVENT_PAGE);
		record->backup = byte;

		if (VMI_FAILURE == vmi_write_8_pa(vmi,pa,&trap)) {
	            printf("FAILED TO INJECT TRAP @ 0x%lx !\n", pa);
	            continue;
	        }
/*	        if(!record->event){//if the memory already being setup events
			record->event = g_malloc0(sizeof(vmi_event_t));
			mm_event[i].mem_event.gla2 = va;//add comparing gla to memory event structure
			mm_event[i].mem_event.hypercall=hypercall_name;
			SETUP_MEM_EVENT(&mm_event[i], pa, VMI_MEMEVENT_PAGE,VMI_MEMACCESS_X, trap_guard);
			if(VMI_FAILURE==vmi_register_event(vmi,&mm_event[i])){
				printf("*** FAILED TO REGISTER MEMORY GUARD @ PAGE 0x%lx ***\n", pa >> 12);
				free(record->event);
				free(record);
				continue;
			};
			record->event->data = g_hash_table_new(g_int64_hash, g_int64_equal);
			printf("New memory event trap set on page 0x%lx\n", pa >> 12);
		} else {
			printf("Memory event trap already set on page 0x%lx\n", pa >> 12);
        	}

	        struct memevent *test = g_hash_table_lookup(record->event->data, &record->pa);
                if (!test) {
		        g_hash_table_insert(record->event->data, &record->pa, record);
                } else if (test->tag==1) {
                	printf("Address is already guarded\n");
                } else {
      	                printf("Address is trapped by another feature! ERROR/TODO!\n");
       	        }
	}
	printf("\nAll %d hypercalls are trapped!\n",num);

	// save trap location into lookup tree
        //g_hash_table_insert(record->pa_lookup, g_memdup(&record->pa, 8), &record->backup);

	vmi_resume_vm(vmi);
	while(!interrupted){
        	status = vmi_events_listen(vmi,500);
	        if (status != VMI_SUCCESS) {
        	    printf("Error waiting for events, quitting...\n");
	            interrupted = -1;
		}
*/
        }

	printf("\nFinished with test.\n");
        vmi_destroy(vmi);
        return 1;
}
