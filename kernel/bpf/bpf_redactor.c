#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/bpf_redactor.h>
#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/filter.h>

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

// Wołane z verifier.c: static int check_helper_call
static const struct bpf_func_proto *
redactor_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
    case BPF_FUNC_get_current_uid_gid:
        return &bpf_get_current_uid_gid_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

// Używana w verifier.c: static int check_ctx_access
static bool redactor_is_valid_access(int off, int size,
					   enum bpf_access_type type,
					   const struct bpf_prog *prog,
					   struct bpf_insn_access_aux *info)
{
    if (off < 0 || off >= sizeof(struct redactor_ctx))
		return false;
	if (type != BPF_READ)
		return false;

    // if is redact
    switch (off) {
    case bpf_ctx_range(struct redactor_ctx, offset):
    case bpf_ctx_range(struct redactor_ctx, size):
        return true;
    }

    switch (off) {
    case bpf_ctx_range(struct redactor_ctx, flags):
    case bpf_ctx_range(struct redactor_ctx, mode):
    case bpf_ctx_range(struct redactor_ctx, uid):
    case bpf_ctx_range(struct redactor_ctx, gid):
        return true;
    }
 
    return false;
}

static bool __redactor_allowed_prog(const struct bpf_prog *prog)
{
    return prog->type == BPF_PROG_TYPE_REDACTOR;
}

struct redactor_info rd_info;

BPF_CALL_4(bpf_copy_to_buffer, struct redactor_ctx *, ctx, unsigned long, offset, void *, ptr, unsigned long, size)
{
    if (offset > rd_info.size)
        return -EINVAL;
    // Avoid overflows
    if (size > rd_info.size - offset)
        return -EINVAL;
    size_t sz = rd_info.size - offset;
    if (size < sz)
        sz = size;
    return copy_to_user(rd_info.buf + offset, ptr, sz);
}

const struct bpf_func_proto bpf_copy_to_buffer_proto = {
    .func = bpf_copy_to_buffer,
    .gpl_only = false,
    .ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_CTX | MEM_RDONLY,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_PTR_TO_MEM,
	.arg4_type = ARG_CONST_SIZE,
    .allowed = __redactor_allowed_prog,
};

BPF_CALL_4(bpf_copy_from_buffer, struct redactor_ctx *, ctx, unsigned long, offset, void *, ptr, unsigned long, size)
{
    if (offset > rd_info.size)
        return -EINVAL;
    size_t sz = rd_info.size - offset;
    if (sz > size)
        sz = size;

    return copy_from_user(ptr, rd_info.buf + offset, sz);
}

const struct bpf_func_proto bpf_copy_from_buffer_proto = {
    .func = bpf_copy_from_buffer,
    .gpl_only = false,
    .ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_CTX | MEM_RDONLY,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_PTR_TO_MEM,
	.arg4_type = ARG_CONST_SIZE,
    .allowed = __redactor_allowed_prog,
};



const struct bpf_prog_ops bpf_redactor_prog_ops = {
};

const struct bpf_verifier_ops bpf_redactor_verifier_ops = {
	.get_func_proto = redactor_func_proto,
	.is_valid_access = redactor_is_valid_access,
};
