package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
	uid_t uid;
	gid_t gid;
	int ret;
	char filename[256];
} chown_event_t;

BPF_PERF_OUTPUT(chown_events);
BPF_HASH(chowncall, u64, chown_event_t);

int kprobe__sys_fchownat(struct pt_regs *ctx, int dfd, const char *filename, uid_t uid, gid_t gid, int flag) {
	bpf_trace_printk("hello, world!\\n");
	u64 pid = bpf_get_current_pid_tgid();
	chown_event_t event = {
		.pid = pid >> 32,
		.uid = uid,
		.gid = gid,
	};
	bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
	chowncall.update(&pid, &event);
	return 0;
}

int kretprobe__sys_fchownat(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	chown_event_t *eventp = chowncall.lookup(&pid);
	if (eventp == 0) {
		return 0;
	}

	chown_event_t event = *eventp;
	event.ret = ret;
	chown_events.perf_submit(ctx, &event, sizeof(event));
	chowncall.delete(&pid);
	return 0;
}
`

type chownEvent struct {
	Pid         uint32
	Uid         uint32
	Gid         uint32
	ReturnValue int32
	Filename    [256]byte
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	// Specify a kernel function
	fnName := bpf.GetSyscallFnName("fchownat")

	// Load user-defined C function to Kprobe
	kprobe, err := m.LoadKprobe("kprobe__sys_fchownat")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load syscall__execve: %s\n", err)
		os.Exit(1)
	}

	// Attach Kprobe to the specific kernel function
	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach syscall_execve: %s\n", err)
		os.Exit(1)
	}

	retKprobe, err := m.LoadKprobe("kretprobe__sys_fchownat")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load kretprobe__sys_chownat: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKretprobe(fnName, retKprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach kretprobe__sys_fchownat: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("chown_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Println("start.")

	go func() {
		var event chownEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			filename := (*C.char)(unsafe.Pointer(&event.Filename))
			fmt.Printf("uid %d gid %d pid %d called fchownat(2) on %s (return value: %d)\n", event.Uid, event.Gid, event.Pid, C.GoString(filename), event.ReturnValue)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
