#include <asm-generic/errno.h>
#include <linux/types.h>
#include <linux/bpf_redactor.h>
#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/file.h>

SYSCALL_DEFINE1(count_redactions, int, fd)
{
    struct fd f = fdget_pos(fd);
    int retval;
    if (!f.file)
        return -EBADF;

    retval = f.file->f_rcnt;
    
    fdput_pos(f);
    return retval;
}

SYSCALL_DEFINE1(reset_redactions, int, fd)
{
    struct fd f = fdget_pos(fd);
    if (!f.file)
        return -EBADF;

    f.file->f_rcnt = 0;
    
    fdput_pos(f);
    return 0;
}

int bpf_redactor_decide(struct redactor_ctx *ctx)
{
    printk("decide");
    return 1;
}

int bpf_redactor_redact(struct redactor_ctx *ctx)
{
    printk("redact");
    return 1;
}

int redactor_bpf_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    printk("attach");
    return 0;
}

int redactor_bpf_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog)
{
    printk("detach");
    return 0;
}


/*
// https://docs.kernel.org/bpf/kfuncs.html
__bpf_kfunc int bpf_copy_to_buffer(void *ctx, unsigned long offset, void *ptr, unsigned long size);

__bpf_kfunc int bpf_copy_from_buffer(void *ctx, unsigned long offset, void *ptr, unsigned long size);
*/