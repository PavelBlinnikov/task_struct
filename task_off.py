import gdb

def dummy_entropy(number):
	count = 0
	number = bin(number)[2:]
	if len(number) == 1:
		return 0
	for i in range(1, len(number)):
		if number[i] != number[i-1]:
			count += 1
	return count

class task_off(gdb.Command):
	tasks = []

	def __init__(self):
		gdb.Command.__init__(self, "task_off", gdb.COMMAND_USER)
	
	def read(self, addr):
		try:
			return int(gdb.selected_inferior().read_memory(addr, 8)[::-1].hex(), 16)
		except OverflowError:
			print(gdb.selected_inferior().read_memory(addr, 8)[::-1].hex(), 16)

	def find_tasks(self, addr):
		base = addr>>32
		for i in range(0x400):
			try:
				cur = self.read(addr + (i * 8))
				self.read(cur)
				prev_cur = self.read(cur + 8)
				next_cur = self.read(cur)
				prev_next_cur = self.read(next_cur + 8)
				if prev_cur == (addr + (i * 8)) and prev_next_cur == cur:
					if cur>>32 != base:
						print(f"[+++] Highly likely offset is ", end='')
					else:
						print(f"[*] Possible offset is ", end='')
					self.tasks.append(i * 8)
					print(f"{hex(i * 8)} and addr is {hex(addr + (i * 8))}")
			except gdb.MemoryError:
				pass
	def find_pid(self, addr):
		for i in range(0x400):
			try:
				cur = self.read(addr + (i * 8))
				if dummy_entropy(cur) > 20 and cur&0xff == 0:
					print(f"[+++] Highly likely offset is {hex((i - 1) * 8)} and addr is {hex(addr + ((i - 1) * 8))}")
			except gdb.MemoryError:
				pass

	def find_cred(self, addr):
		for i in range(0x400):
			try:
				if b'swapper' in (gdb.selected_inferior().read_memory(addr + (i * 8), 8).tobytes()):
					print(f"[+++++] Offset to COMM[!!!] is {hex((i) * 8)} and addr is {hex(addr + ((i) * 8))}")
					print(f"[*****] Please be careful that this is not the address of struct cred*. It is somewhere near.")
			except gdb.MemoryError:
				pass
	
	def verify_tasks(self, addr):
		for i in self.tasks:
			try:
				next_addr = self.read(addr + i) - i
				for j in range(0x400):
					cur = self.read(next_addr + (j * 8))
					if cur == 0x0000000100000001:
						temp = self.read(addr + (j * 8))
						if temp == 0:
							print(f"[+++++] Extremely likely that {hex(i)} is the offset for TASKS")
							print(f"        and {hex(j * 8)} is the offset for PID")
			except gdb.MemoryError:
				pass

	def invoke(self, args, from_tty):
		args = args.split(' ')
		if len(args) < 1:
			print("task_off [task_struct address]")
			return
		task = int(args[0], 16)
		print("\t\t[***] TASKS OFFSET [***]")
		self.find_tasks(task)
		print("\n\t\t[***] PID OFFSET [***]")
		self.find_pid(task)
		print("\n\t\t[***] CRED OFFSET [***]")
		self.find_cred(task)
		print('\n\t\t[***] VERIFICATION [***]')
		self.verify_tasks(task)
		
		
task_off()
