# Incident serial logs

Captured serial output from QEMU boots that back findings on specific
issues. Each file is the literal serial stream; trust the file, not this
README. Cross-reference the issue number in the filename to get full
context.

## Index

| File | Issue | What it shows |
|---|---|---|
| `502-fork-trace-boot.log` | [#502](https://github.com/dburkart/vibix/issues/502) | Full `fork-trace` probe stream from one clean boot — fork(2) syscall path instrumented end-to-end, all probes fire, `IF=0` confirmed at dispatch, `[C]` marker shows the child reached `fork_child_sysret`. Also used as the primary evidence source for the #503 typing-dead write-up (`../fork-hang/typing-dead.md`). |

## Reproducing a capture

Build the kernel with the `fork-trace` feature (lives in
`kernel/Cargo.toml`) and boot QEMU with the test disk image:

```sh
cargo xtask iso --fork-trace
qemu-system-x86_64 \
  -M q35 -cpu max -m 256M \
  -serial file:/tmp/serial.log -display none \
  -no-reboot -no-shutdown \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -drive file=target/test-disk.img,if=none,id=vd0,format=raw \
  -device virtio-blk-pci,drive=vd0,disable-modern=on,disable-legacy=off \
  -cdrom target/vibix.iso
```

Kill QEMU after `init: fork+exec+wait ok` appears in the log (or after
~30 seconds if the kernel hangs). The probe strings all start with
`fork-trace:`; the lone `C` on its own line is the asm-level `COM1`
poke that fires only when the child task has successfully reached the
`fork_child_sysret` trampoline (last moment before `SYSRETQ`).
