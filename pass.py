import tkinter as tk
from tkinter.scrolledtext import ScrolledText

main=tk.Tk()
main.configure(background="grey74")
main.geometry("400x200")




def click_enter():
      global frame1,frame2,store_pass,textarea
      check_pass=store_pass.get()
      if (check_pass=="walletpassword"):
          frame1.destroy()
          main.geometry("500x500")
          frame2 = tk.LabelFrame (main , text = "PASS-WALLET")
          frame2.pack(fill="x",expand=False)
          heading=tk.Message(frame2, text ="Enter your secret data", width=125)
          heading.pack(fill="x",expand=True)
          scrollbar = tk.Scrollbar(frame2)
          scrollbar.pack(side="right", fill="y")


          textarea=tk.Text(frame2,yscrollcommand=scrollbar.set)
          textarea.pack(fill="both",expand=True)


          scrollbar.config(command=textarea.yview)

          Add_Button=tk.Button(main , text="Save", command =on_save_click, relief= "raised" )
          Add_Button.place(x=245,y=440)
          Enter_Button.destroy()
      else:
          tk.Label(frame1,text="Retry").grid(row=1,columnspan=2)


    global textarea
    store_data=textarea.get('1.0',"end")
    with open("test.pas", "w") as file:
        file.writelines(store_data)




frame1 = tk.LabelFrame (main , text = "PASS-WALLET")
frame1.place(relx=0.5,rely=0.5, anchor="center")
tk.Message(frame1, text ="Enter the password to access your wallet", width=125).grid(row = 0,column = 0 )
store_pass= tk.StringVar()
init_pass=tk.Entry(frame1,show="•",textvariable=store_pass).grid(row = 0 ,column = 1 )

Enter_Button=tk.Button(main , text="Enter", command = click_enter, relief= "raised" )
Enter_Button.place(x=180,y=140)





main.mainloop()
