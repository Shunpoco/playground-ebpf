package main

import (
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
int hello(void *ctx) {
	bpf_trace_printk("hello, world!\\n");
	return 0;
}
`

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	fnName := bpf.GetSyscallFnName("clone")

	kprobe, err := m.LoadKprobe("hello")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load hello: %s\n", err)
		os.Exit(1)
	}

	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach hello: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		for {
		}
	}()

	<-sig
}
