#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_redactor

#if !defined(_TRACE_BPF_REDACTOR_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_REDACTOR_H

#include <linux/bpf_redactor.h>
#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(bpf_redactor_decide,
	TP_PROTO(struct redactor_ctx *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(u64, flags)
	),

	TP_fast_assign(
		__entry->flags        = ctx->flags;
	),

	TP_printk("flags %llu", __entry->flags)
);

#endif // _TRACE_BPF_REDACTOR_H
#include <trace/define_trace.h>