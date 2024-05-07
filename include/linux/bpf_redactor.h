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

bool redactor_is_decide_type(const struct bpf_prog *prog);
bool redactor_is_redact_type(const struct bpf_prog *prog);

int redactor_bpf_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int redactor_bpf_prog_detach(const union bpf_attr *attr, struct bpf_prog *prog);


#endif // __BPF_REDACTOR_H