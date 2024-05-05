#include <linux/types.h>
#include <linux/bpf_redactor.h>
#include <linux/printk.h>

const struct bpf_prog_ops bpf_redactor_prog_ops = {
};

const struct bpf_verifier_ops bpf_redactor_verifier_ops = {
//	.get_func_proto = bpf_tracing_func_proto,
//	.is_valid_access = btf_ctx_access, // ewentualnie to do zmiany
};

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