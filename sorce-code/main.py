from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys
import base64
import random
from prettytable import PrettyTable

FONT=("Helvetica",13,"normal")
key=None
lower = "abcdefghijklmnopqrstuvwxyz"
upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
numbers = "0123456789"
symbols = "@#$&_-()=%*:/!?+."

# ---------------------------- PRINT PASSWORD  ------------------------------- #
def decryptPasswordsFromFile():
    decrypted_passwords = []
    with open("notMyPass.txt", 'r') as file:
        for line in file:
            parts = line.strip().split('|')  # Assuming | is the separator
            name = parts[0].strip()
            email = parts[1].strip()
            encrypted_password = parts[2].strip()
            refKey=Fernet(key)
            try:
              decrypted_password = refKey.decrypt(eval(encrypted_password)).decode('utf-8')
              decrypted_passwords.append((name, email, decrypted_password))
            except:
              continue
    printToScreen(decrypted_passwords) 

def printToScreen(passwords_list):
    info = Tk()
    info.withdraw()
    table = PrettyTable()
    table.field_names = ["Website", "Email", "Password"]

    for entry in passwords_list:
        # Left-align each entry within its column
        website = entry[0].ljust(20)
        email = entry[1].ljust(30)
        password = entry[2].ljust(20)
        
        table.add_row([website, email, password])

    formatted_text = table.get_string()

    # Create a custom-sized window to display the formatted text
    custom_window = Toplevel(info)
    custom_window.title("Password List")
    custom_window.geometry("1000x600")  # Adjust the width and height as needed

    text_widget = Text(custom_window, wrap=WORD)
    text_widget.pack(fill=BOTH, expand=True)
    text_widget.insert(END, formatted_text)
    text_widget.config(state=DISABLED)  # Make the text widget read-only
    def on_close():
        custom_window.destroy()  # Ensure the window is destroyed
        custom_window.quit()

    custom_window.protocol("WM_DELETE_WINDOW", on_close)  # Call on_close when the X button is clicked

    custom_window.mainloop()
# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def genPass():
  string = lower + upper + numbers + symbols
  password = "".join(random.sample(string, 12))
  pass_input.insert(END,password)
# ---------------------------- SAVE PASSWORD ------------------------------- #
def getKey():
  global key

  bytes_pass=bytes(secret_input.get(), encoding='utf-8')
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    iterations=100000, 
    salt=b'',
    length=32
)
  key = base64.urlsafe_b64encode(kdf.derive(bytes_pass))
  root.destroy()
  root.quit()

def encryptPass(password):
  refKey = Fernet(key)
  mypwdbyt = bytes(password, 'utf-8')
  return refKey.encrypt(mypwdbyt)

def savePass():
  website=website_input.get()
  email=user_input.get()
  password=encryptPass(pass_input.get())

  if website == '' or email == '' or pass_input.get() == '':
    messagebox.showinfo(title="error", message="please dont leave anything empty")
    return
  is_ok=messagebox.showinfo(title=website, message=f"this is the details entered: \nEmail: {email} \nPassword: {pass_input.get()} \nIs it ok to save?")
  if is_ok:
    data=f" {website}  |  {email}  |  {password} \n"
    if not (os.path.exists("notMyPass.txt")):
      with open("notMyPass.txt", 'w') as f:
          f.write("")
    with open("notMyPass.txt", "r+") as f:
      text = f.read()
      if data in text:
        return
      f.write(data)
# ---------------------------- UI SETUP ------------------------------- #



#secret-window
root = Tk()
root.title("secret")
root.config(padx=20,pady=20)
secret_input = Entry(root,width=20,font=FONT,show="*")
secret_btn = Button(root, text="Okay",width=10, command = getKey)
secret_btn.grid(row=0,column=1,padx=10)
secret_input.grid(row=0,column=0,padx=10)
def disable_event():
    pass
root.protocol("WM_DELETE_WINDOW", disable_event)
root.mainloop()

#main
screen=Tk()
screen.config(padx=50,pady=50)
screen.title("pass manger")

#canvas-photo
img=PhotoImage(file="logo.png")
logo=Canvas(width=200,height=200)
logo.create_image(100,100,image=img)

#labels
website_text = Label(text="Website: ")
user_text = Label(text="Email/Username: ")
pass_text = Label(text="password: ")

#input
website_input=Entry(width=35,font=FONT)
website_input.focus()
user_input=Entry(width=35,font=FONT)
user_input.insert(0,"deviddevid287@gmail.com")
pass_input=Entry(width=23,font=FONT)

#btns
gen_pass_btn=Button(text="Generate Password",command=genPass)
add_info_btn=Button(text="Add",width=44,command=savePass)
get_info_btn=Button(text="Print Password",width=44,command=decryptPasswordsFromFile)

#layout
logo.grid         (column=1,row=0,pady=3)
website_text.grid (column=0,row=1,pady=3)
user_text.grid    (column=0,row=2,pady=3)
pass_text.grid    (column=0,row=3,pady=3)
website_input.grid(column=1,row=1,columnspan=2,pady=3)
user_input.grid   (column=1,row=2,columnspan=2,pady=3)
pass_input.grid   (column=1,row=3,pady=3,sticky = 'e',padx=3)
gen_pass_btn.grid (column=2,row=3)
add_info_btn.grid (column=1,row=4,columnspan=2,pady=3)
get_info_btn.grid (column=1,row=5,columnspan=2,pady=3)

def closeAll():
        screen.destroy()
        screen.quit()
screen.protocol("WM_DELETE_WINDOW", closeAll)
screen.mainloop()