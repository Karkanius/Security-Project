"""
=====================================================================================

         Module:  Logger

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""


import sys

def log(topic, message, aspect):
	if(aspect=="violet"):
		print(f"{bcolors.VIOLET}",end='')
	elif(aspect=="blue"):
		print(f"{bcolors.BLUE}",end='')
	elif(aspect=="green"):
		print(f"{bcolors.GREEN}",end='')
	elif(aspect=="yellow"):
		print(f"{bcolors.YELLOW}",end='')
	elif(aspect=="red"):
		print(f"{bcolors.RED}",end='')
	elif(aspect=="bold"):
		print(f"{bcolors.BOLD}",end='')
	elif(aspect=="underline"):
		print(f"{bcolors.UNDERLINE}",end='')
	print("[{0}] {1}{2}".format(topic,message,bcolors.ENDC))

class bcolors:
    VIOLET = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'