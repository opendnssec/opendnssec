import subprocess
import Util

verbosity = 3;

def debug(level, message):
	if level <= verbosity:
		print(message)

def run_tool(command, input=None):
	Util.debug(5, "Command: '"+" ".join(command)+"'")
	if (input):
		p = subprocess.Popen(command, stdin=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	else:
		p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	return p


