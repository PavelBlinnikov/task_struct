# task_struct offset guesser
This is the tool that designed to guess offsets in task_struct structure in the Linux kernel that compiled without debug symbols.
```bash
source task_off.py
task_off 0xffffffff82a1a940 # address of init_task
```
