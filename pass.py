import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import os
import hashlib
import base64
import winsound
import binascii
import _thread
import time
from PIL import ImageTk, Image
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
#from passlib.hash import pbkdf2_sha256

main_window=tk.Tk()   #main_window the root container
main_window.configure(background="#393640")
main_window.geometry("400x200")

default_password='walletpassword'
my_password=""


def create_save_password(password):
    m = hashlib.md5()
    m.update(password)
    with open("pass.wal", "w") as file:
        file.writelines(m.hexdigest())
        file.close()

if (not os.path.isfile('pass.wal')):
    tk.Label(main_window,text="DEFAULT PASSWORD = walletpassword").place(x=100,y=175)
    create_save_password(str.encode(default_password))


def check_password(password):
    m = hashlib.md5()
    m.update(password)
    with open("pass.wal","r") as ofile:
         content = ofile.read()
         if(m.hexdigest() == content):
             return True
         else:
             return False





def click_enter(self):
      global frame1,frame2,store_pass,textarea,my_password,encrypted_data
      check_pass=store_pass.get()


      if (check_password(str.encode(check_pass))):
          frame1.destroy()
          frame.destroy()
          main_window.geometry("500x500")
          main_window.configure(background="azure4")
          frame2 = tk.LabelFrame (main_window , text = "PASS-WALLET")
          frame2.pack(fill="x",expand=False)
          heading=tk.Message(frame2, text ="Enter your secret data", width=125)
          heading.pack(fill="x",expand=True)
          scrollbar = tk.Scrollbar(frame2)
          scrollbar.pack(side="right", fill="y")

          textarea=tk.Text(frame2,yscrollcommand=scrollbar.set)
          textarea.pack(fill="both",expand=True)
          if os.path.exists("data.wal"):
              with open("data.wal","rb") as ofile:
                  content=ofile.read()
                  key = make_key(str.encode(my_password))
                  cipher=Fernet(key)
                  decrypted_data=cipher.decrypt(bytes(content))
                  textarea.insert("end",decrypted_data)
          else:
              with open("data.wal","w+") as ofile:
                  content=ofile.write('')
                  textarea.insert("end",content)

          scrollbar.config(command=textarea.yview)

          Add_Button=tk.Button(main_window , text="  Save the data  ", command =on_save_click, relief= "raised" )
          Add_Button.place(x=300,y=440)

          Change_Pass_Button=tk.Button(main_window , text=" Change Password ", command =on_change_pass_click, relief= "raised" )
          Change_Pass_Button.place(x=100,y=440)

          Enter_Button.destroy()
      else:
          tk.Label(frame1,text="Retry! not the correct password").grid(row=1,columnspan=2)




def click_confirm(self):
     global store_old_pass,store_new_pass,my_password,change_pass_window
     if (len (store_new_pass.get())<=5):
         tk.Label(frame3,text="Retry! with more than 5 characters").grid(row=2,columnspan=2)

     else:
         check_old_pass=store_old_pass.get()

         if(check_password(str.encode(check_old_pass))):
                 create_save_password(str.encode(store_new_pass.get()))
                 on_save_click()
                 change_pass_window.destroy()
         else:
                 tk.Label(frame3,text="Retry! with correct previous password").grid(row=2,columnspan=2)



def on_save_click():
    global textarea,encrypted_data

    with open("data.wal", "wb") as file:
        global my_password
        key=make_key(str.encode(my_password))
        store_data=textarea.get('1.0',"end")
        cipher=Fernet(key)
        encrypted_data=cipher.encrypt(store_data.encode('ascii'))
        file.write(encrypted_data)

    winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS)

def make_key(password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password)
    return base64.urlsafe_b64encode(digest.finalize())


def on_change_pass_click():
    global store_old_pass,store_new_pass,my_password,frame3,change_pass_window
    change_pass_window = tk.Toplevel(main_window)
    change_pass_window.geometry("300x300")
    change_pass_window.configure(background="azure4")

    frame3=tk.Frame(change_pass_window)
    frame3.place(x=150,y=100, anchor="center")
    tk.Label(frame3,text="Enter old password").grid(row = 0 ,column=0,pady=5)
    store_old_pass= tk.StringVar()
    old_pass=tk.Entry(frame3,show="•",textvariable=store_old_pass)
    old_pass.grid(row=0,column=1,pady=5,padx=2)
    tk.Label(frame3,text="Enter new password").grid(row = 1,column=0,pady=5 )
    store_new_pass= tk.StringVar()
    new_pass=tk.Entry(frame3,show="•",textvariable=store_new_pass)
    new_pass.grid(row=1,column=1,pady=5,padx=2)

    Confirm_Button=tk.Button(change_pass_window , text="Confirm", command = lambda: click_confirm(0), relief= "raised" )
    Confirm_Button.place(x=125,y=160)



frame=tk.Frame(main_window)
frame.pack()
photo=ImageTk.PhotoImage(Image.open(r'heading.jpg'))
w=tk.Label(frame, image=photo)
w.pack()


frame1 = tk.LabelFrame (main_window )
frame1.place(relx=0.5,rely=0.5, anchor="center")
tk.Message(frame1, text ="Enter the password to access your wallet", width=125).grid(row = 0,column = 0 )
store_pass= tk.StringVar()
init_pass=tk.Entry(frame1,show="•",textvariable=store_pass)
init_pass.grid(row = 0 ,column = 1 )
init_pass.bind('<Return>', click_enter)  #whenever enterkey is pressed try opening the wallet

Enter_Button=tk.Button(main_window , text="Enter", command = lambda: click_enter(0), relief= "raised" )
Enter_Button.place(x=180,y=140)



main_window.mainloop()
