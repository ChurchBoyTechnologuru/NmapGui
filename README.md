To Install 
use sudo dpkg -i advanced-nmap-gui_1.0_all.deb
this simplifies the process of typing and retyping commands
I have used customtkinter a python gui framework based on tkinter
for custom tkinter
 1. Update Your System

sudo apt update && sudo apt upgrade -y

2. Install Required Dependencies

sudo apt install python3-pip python3-tk python3-venv -y

3. Install customtkinter

Now install customtkinter using pip:

pip3 install customtkinter

If you get the PEP 668 error (--break-system-packages), use:

pip3 install customtkinter --break-system-packages
