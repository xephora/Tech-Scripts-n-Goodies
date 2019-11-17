import tkinter as tk
from tkinter import Tk, filedialog, Text, Button, Frame, Entry, END
import os
import wmi
import getpass

ip_addr = raw_input('Host/IP: ')

class base(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.pack()  

def funcCheckFS():
	print('Users')
	files = [f for f in os.listdir('\\\\' + ip_addr + '\\c$\\users') if os.path.isfile(f)]
	for f in files:
		print(files)
	target_user = raw_input('Target Username?: ')
	print('Local')
	files = [f for f in os.listdir('\\\\' + ip_addr + '\\c$\\users\\' + target_user + '\\appdata\\local') if os.path.isfile(f)]
	for f in files:
		print(files)
	print('Roaming')
	files = [f for f in os.listdir('\\\\' + ip_addr + '\\c$\\users\\' + target_user + '\\appdata\\roaming') if os.path.isfile(f)]
	for f in files:
		print(files)

def funcCheckProcesses():
	username = raw_input('Username: ')
	passwordw = getpass.getpass('Password: ')
	conn = wmi.WMI(ip_addr, user=username, password=passwordw)
	for process in conn.Win32_Process():
		print("ID: {0}\nHandleCount: {1}\nProcessName: {2}\n".format(
		process.ProcessId, process.HandleCount, process.Name
		)
		)

foundation = Tk()
face = tk.Canvas()
frame = base(master=foundation)
frame.master.title('test gui')
foundation.geometry('200x200')

b = Button(foundation, text="Check Remote FileSystem", command=funcCheckFS)
b.pack()
d = Button(foundation, text="Check Remote Processes", command=funcCheckProcesses)
d.pack()

foundation.mainloop()
foundation.destroy()

