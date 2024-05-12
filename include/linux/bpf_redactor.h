#ifndef __BPF_REDACTOR_H
#define __BPF_REDACTOR_H
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/bpf.h>
#include <linux/spinlock.h>

struct redactor_ctx {
union {
        struct {
                loff_t offset;
                size_t size;
        };
        struct {
                u64 flags;
                umode_t mode;
                kuid_t uid;
                kgid_t gid;
        };
};
};

struct redactor_info {
        char __user *buf;
        size_t size;
};

struct redactor_ctx_kern {
        struct redactor_info info;
        struct redactor_ctx ctx;
};

int bpf_redactor_decide(struct redactor_ctx_kern *ctx);
int bpf_redactor_redact(struct redactor_ctx_kern *ctx);

struct redactor_ctx_kern create_decide_ctx(const struct open_how *how);

#endif // __BPF_REDACTOR_H