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

    spin_lock(&f.file->f_rlock);
    if (!f.file->f_ron) {
        retval = -EINVAL;
        goto cleanup;
    }

    retval = f.file->f_rcnt;

cleanup:
 	spin_unlock(&f.file->f_rlock);
    fdput_pos(f);
    return retval;
}

SYSCALL_DEFINE1(reset_redactions, int, fd)
{
    struct fd f = fdget_pos(fd);
    int retval;
    if (!f.file)
        return -EBADF;

    spin_lock(&f.file->f_rlock);
    if (!f.file->f_ron) {
        retval = -EINVAL;
        goto cleanup;
    }
    
    f.file->f_rcnt = 0;
    retval = 0;

cleanup:
 	spin_unlock(&f.file->f_rlock);
    fdput_pos(f);
    return retval;
}

int bpf_redactor_decide(struct redactor_ctx *ctx)
{
    return 0;
}

int bpf_redactor_redact(struct redactor_ctx *ctx)
{
    return 0;
}

struct redactor_ctx create_decide_ctx(const struct open_how *how)
{
    return (struct redactor_ctx) {
        .flags = how->flags,
		.mode = how->mode,
		.uid = current_uid(),
		.gid = current_gid(),
	};
}

struct redactor_ctx create_redact_ctx(void)
{
    return (struct redactor_ctx) {
        .offset = 0,
        .size = 0,
    };
}


static const struct bpf_func_proto *
redactor_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool redactor_is_valid_access(int off, int size,
					   enum bpf_access_type type,
					   const struct bpf_prog *prog,
					   struct bpf_insn_access_aux *info)
{
    return false;
}

const struct bpf_prog_ops bpf_redactor_prog_ops = {
};

const struct bpf_verifier_ops bpf_redactor_verifier_ops = {
	.get_func_proto = redactor_func_proto,
	.is_valid_access = redactor_is_valid_access, // ewentualnie to do zmiany
};


/*
// https://docs.kernel.org/bpf/kfuncs.html
// https://elixir.bootlin.com/linux/v5.13-rc1/source/kernel/bpf/helpers.c#L20
__bpf_kfunc int bpf_copy_to_buffer(void *ctx, unsigned long offset, void *ptr, unsigned long size);

__bpf_kfunc int bpf_copy_from_buffer(void *ctx, unsigned long offset, void *ptr, unsigned long size);
*/