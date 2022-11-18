import gdb

class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "light_gray"     : "\033[0;37m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "cyan"           : "\033[36m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    @staticmethod
    def redify(msg: str) -> str:        return Color.colorify(msg, "red")
    @staticmethod
    def greenify(msg: str) -> str:      return Color.colorify(msg, "green")
    @staticmethod
    def blueify(msg: str) -> str:       return Color.colorify(msg, "blue")
    @staticmethod
    def yellowify(msg: str) -> str:     return Color.colorify(msg, "yellow")
    @staticmethod
    def grayify(msg: str) -> str:       return Color.colorify(msg, "gray")
    @staticmethod
    def light_grayify(msg: str) -> str: return Color.colorify(msg, "light_gray")
    @staticmethod
    def pinkify(msg: str) -> str:       return Color.colorify(msg, "pink")
    @staticmethod
    def cyanify(msg: str) -> str:       return Color.colorify(msg, "cyan")
    @staticmethod
    def boldify(msg: str) -> str:       return Color.colorify(msg, "bold")
    @staticmethod
    def underlinify(msg: str) -> str:   return Color.colorify(msg, "underline")
    @staticmethod
    def highlightify(msg: str) -> str:  return Color.colorify(msg, "highlight")
    @staticmethod
    def blinkify(msg: str) -> str:      return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text: str, attrs: str) -> str:
        """Color text according to the given attributes."""

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg:   msg.append(colors["highlight_off"])
        if colors["underline"] in msg:   msg.append(colors["underline_off"])
        if colors["blink"] in msg:       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)

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
	color_machine = Color()

	def __init__(self):
		gdb.Command.__init__(self, "task_off", gdb.COMMAND_USER)
	
	def read(self, addr):
		try:
			return int(gdb.selected_inferior().read_memory(addr, 8)[::-1].hex(), 16)
		except OverflowError:
			print(gdb.selected_inferior().read_memory(addr, 8)[::-1].hex(), 16)

	def colorify(self, text):
		if '+' in text:
			return self.color_machine.boldify(self.color_machine.greenify(text))
		elif '*' in text:
			return self.color_machine.boldify(self.color_machine.blueify(text))
		elif '-' in text:
			return self.color_machine.boldify(self.color_machine.redify(text))
		else:
			return text

	def numberify(self, text):
		return self.color_machine.pinkify(self.color_machine.boldify(text))

	def find_tasks(self, addr):
		base = addr>>32
		for i in range(0x200):
			try:
				cur = self.read(addr + (i * 8))
				self.read(cur)
				prev_cur = self.read(cur + 8)
				next_cur = self.read(cur)
				prev_next_cur = self.read(next_cur + 8)
				if prev_cur == (addr + (i * 8)) and prev_next_cur == cur:
					if cur>>32 != base:
						print(self.colorify("[+++]") + f" Highly likely offset is ", end='')
					else:
						print(self.colorify("[*]") + f" Possible offset is ", end='')
					self.tasks.append(i * 8)
					print(f"{self.numberify(hex(i * 8))} and addr is {hex(addr + (i * 8))}")
			except gdb.MemoryError:
				pass
	def find_pid(self, addr):
		for i in range(0x200):
			try:
				cur = self.read(addr + (i * 8))
				if dummy_entropy(cur) > 20 and cur&0xff == 0:
					print(self.colorify("[+++]") + f" Highly likely offset is {self.numberify(hex((i - 1) * 8))} and addr is {hex(addr + ((i - 1) * 8))}")
			except gdb.MemoryError:
				pass

	def find_cred(self, addr):
		for i in range(0x200):
			try:
				if b'swapper' in (gdb.selected_inferior().read_memory(addr + (i * 8), 8).tobytes()):
					print(self.colorify("[+++++]") + f" Offset to COMM[!!!] is {self.numberify(hex((i) * 8))} and addr is {hex(addr + ((i) * 8))}")
					print(self.colorify("[*****]") + f" Please be careful that this is not the address of struct cred*. It is somewhere near.")
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
							print(self.colorify("[+++++]") + f" Extremely likely that {self.numberify(hex(i))} is the offset for TASKS")
							print(f"\tand {self.numberify(hex(j * 8))} is the offset for PID")
			except gdb.MemoryError:
				pass

	def invoke(self, args, from_tty):
		args = args.split(' ')
		if len(args) < 1:
			print("task_off [task_struct address]")
			return
		task = int(args[0], 16)
		print("\t\t" + self.colorify("[***]") + " TASKS OFFSET " + self.colorify("[***]"))
		self.find_tasks(task)
		print("\n\t\t" + self.colorify("[***]") + " PID OFFSET " + self.colorify("[***]"))
		self.find_pid(task)
		print("\n\t\t" + self.colorify("[***]") + " CRED OFFSET " + self.colorify("[***]"))
		self.find_cred(task)
		print("\n\t\t" + self.colorify("[***]") + " VERIFICATION " + self.colorify("[***]"))
		self.verify_tasks(task)
		
		
task_off()
