package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// `-g` is required for generating BTF
//go:generate clang program.bpf.c -o program.bpf.o -target bpf -c -g -O2 -I./include

var printVerifierLog = true

func main() {
	ebpfObjectPath := "program.bpf.o"
	collectionSpec, err := ebpf.LoadCollectionSpec(ebpfObjectPath)
	if err != nil {
		fmt.Println("loading spec: ", err)
	}
	// load
	collection, err := ebpf.NewCollection(collectionSpec)
	if err != nil {
		println("LOAD ERROR:", err.Error())
		if printVerifierLog {
			var verr *ebpf.VerifierError
			if errors.As(err, &verr) {
				for _, v := range verr.Log {
					println(v)
				}
			}
		}
		return
	}
	// attach
	var l link.Link = nil
	for progName, progSpec := range collectionSpec.Programs {
		prog := collection.Programs[progName]
		switch progSpec.Type {
		case ebpf.Kprobe:
			if strings.HasPrefix(progSpec.SectionName, "kprobe") {
				l, err = link.Kprobe(progSpec.AttachTo, prog, nil)
			} else if strings.HasPrefix(progSpec.SectionName, "uprobe") {
				path_and_function := strings.SplitN(progSpec.SectionName, "/", 2)[1]
				parts := strings.SplitN(path_and_function, ":", 2)
				ex, _ := link.OpenExecutable(parts[0])
				l, err = ex.Uprobe(parts[1], prog, nil)
			}
		case ebpf.TracePoint:
			parts := strings.Split(progSpec.AttachTo, "/")
			l, err = link.Tracepoint(parts[0], parts[1], prog, nil)
		case ebpf.RawTracepoint:
			l, err = link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    progSpec.AttachTo,
				Program: prog,
			})
		case ebpf.LSM:
			l, err = link.AttachLSM(link.LSMOptions{
				Program: prog,
			})
		default:
			panic(fmt.Sprintf("Type not supported: %s", progSpec.Type))
		}
		if err != nil {
			println("ATTACH ERROR:", err.Error())
		} else {
			println("ATTACH PROG SUCCESS: ", progName, " link: ", l)
			l.Close()
		}
	}
}
