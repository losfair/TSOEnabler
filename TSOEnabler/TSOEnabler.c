//
//  TSOEnabler.c
//  TSOEnabler
//
//  Created by Saagar Jha on 7/29/20.
//

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <stddef.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <ptrauth.h>

#define TSO_OFFSET 0x4f8

// macOS 11.1, t8101
#define unslid_printf 0xfffffe000725627c

/*
 fffffe0007266cfc: 7f 23 03 d5           pacibsp
 fffffe0007266d00: f8 5f bc a9           stp     x24, x23, [sp, #-64]!
 fffffe0007266d04: f6 57 01 a9           stp     x22, x21, [sp, #16]
 fffffe0007266d08: f4 4f 02 a9           stp     x20, x19, [sp, #32]
 fffffe0007266d0c: fd 7b 03 a9           stp     x29, x30, [sp, #48]
 fffffe0007266d10: fd c3 00 91           add     x29, sp, #48
 fffffe0007266d14: f7 03 02 aa           mov     x23, x2
 fffffe0007266d18: f6 03 01 aa           mov     x22, x1
 fffffe0007266d1c: f3 03 00 aa           mov     x19, x0
 fffffe0007266d20: 28 42 3b d5           mrs     x8, DAIF
 fffffe0007266d24: 48 00 38 37           tbnz    w8, #7, #8 <_sched_perfcontrol_update_callback_deadline+0xdc>
 fffffe0007266d28: df 47 03 d5           msr     DAIFSet, #7
 fffffe0007266d2c: 29 00 80 52           mov     w9, #1
 fffffe0007266d30: 34 1d 68 0a           bic     w20, w9, w8, lsr #7
 fffffe0007266d34: 75 82 02 91           add     x21, x19, #160
 fffffe0007266d38: e0 03 15 aa           mov     x0, x21
 fffffe0007266d3c: a1 a3 ff 97           bl      #-94588 <_lck_attr_free+0x9c>
 */
#define unslid_thread_bind_cluster_type 0xfffffe0007266cfc

static void (*thread_bind_cluster_type)(thread_t, char);

static char *get_thread_pointer(void) {
	char *pointer = NULL;
	// Yes, a mrs x0, tpidr_el1; ret would work, but I'm trying to minimize inline assembly
	__asm__ volatile("mrs %0, tpidr_el1": "=r"(pointer)::);
	return pointer;
}

static int sysctl_tso_enable SYSCTL_HANDLER_ARGS {
	printf("TSOEnabler: got request from %d\n", proc_selfpid());
	
	char *thread_pointer = get_thread_pointer();
	if (!thread_pointer) {
		return KERN_FAILURE;
	}
	
	int in;
	int error = SYSCTL_IN(req, &in, sizeof(in));
	
	// Write to TSO
	if (!error && req->newptr) {
		printf("TSOEnabler: setting TSO to %d\n", in);
        thread_pointer[TSO_OFFSET] = in;
        if(in) {
            printf("TSOEnabler: binding to P cluster\n");
            thread_bind_cluster_type(current_thread(), 'P');
        }
	// Read TSO
	} else if (!error) {
		int out = thread_pointer[TSO_OFFSET];
		printf("TSOEnabler: TSO is %d\n", out);
		error = SYSCTL_OUT(req, &out, sizeof(out));
	}
	
	if (error) {
		printf("TSOEnabler: request failed with error %d\n", error);
	}
	
	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, tso_enable, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY, NULL, 0, &sysctl_tso_enable, "I", "Enable TSO");

kern_return_t TSOEnabler_start(kmod_info_t *ki, void *d) {
	printf("TSOEnabler: TSOEnabler_start()\n");
    sysctl_register_oid(&sysctl__kern_tso_enable);
    
    uintptr_t unauthenticated_printf = (uintptr_t)ptrauth_strip((void *)printf, ptrauth_key_function_pointer);
    thread_bind_cluster_type = (void (*)(thread_t, char))ptrauth_sign_unauthenticated((void *)(unauthenticated_printf + (unslid_thread_bind_cluster_type - unslid_printf)), ptrauth_key_function_pointer, 0);
    printf("TSOEnabler: found thread_bind_cluster_type at %p\n", thread_bind_cluster_type);
    
	return KERN_SUCCESS;
}

kern_return_t TSOEnabler_stop(kmod_info_t *ki, void *d) {
	sysctl_unregister_oid(&sysctl__kern_tso_enable);
	printf("TSOEnabler: TSOEnabler_stop()\n");
    return KERN_SUCCESS;
}
