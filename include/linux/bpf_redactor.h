#ifndef __BPF_REDACTOR_H
#define __BPF_REDACTOR_H
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/bpf.h>

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

int bpf_redactor_decide(struct redactor_ctx *ctx);
int bpf_redactor_redact(struct redactor_ctx *ctx);

struct redactor_ctx create_decide_ctx(const struct open_how *how);
struct redactor_ctx create_redact_ctx(void);

#endif // __BPF_REDACTOR_H