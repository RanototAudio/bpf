#!/usr/bin/env python3
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int add_syscall(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   return 0;
}
"""

b = BPF(text=program)
# syscall = b.get_syscall_fnname("execve")
# openat = b.get_syscall_fnname("openat")
# b.attach_kprobe(event=syscall, fn_name="add_syscall")
# b.attach_kprobe(event=openat, fn_name="add_openat")

# Attach to a tracepoint that gets hit for all syscalls 
b.attach_raw_tracepoint(tp="sys_enter", fn_name="add_syscall")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)