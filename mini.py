import onetimepad
# import tkinter module
from tkinter import *

# import other necessery modules
import random
import time
import datetime

# creating root object
root = Tk()

# defining size of window
root.geometry("1200x6000")

# setting up the title of window
root.title("Message Encryption and Decryption")
#flat, groove, raised, ridge, solid, or sunken
Tops = Frame(root, width=1600)
Tops.pack(side=TOP)

f1 = Frame(root, width=800, height=700,
           relief=SUNKEN)
f1.pack(side=LEFT)

# ==============================================
#                  TIME
# ==============================================
localtime = time.asctime(time.localtime(time.time()))

lblInfo = Label(Tops, font=('helvetica', 50, 'bold'),
                text="Vigenèrecipher and vermancipher ",relief="sunken",
                fg="Black",bg="light blue", bd=10, anchor='w')

lblInfo.grid(row=0, column=0)

lblInfo = Label(Tops, font=('arial', 20, 'bold'),
                text=localtime,bg="light blue",relief="sunken",borderwidth=5,
                bd=10, anchor='w')

lblInfo.grid(row=1, column=0)

rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()
type = StringVar()

def showmsg():
    ori_mess=Msg.get();
    org_key=key.get();

# exit function
def qExit():
    root.destroy()

# Function to reset the window
def Reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")
    type.set("")

#Vigenèrecipher
def encode(key,clear):
    enc=[]
    for i in range(len(clear)):
        key_c=key[i%len(key)]
        enc_c=(ord(clear[i])+ord(key_c))%26
        enc_c+=ord('A')
        enc.append(chr(enc_c))
    return ("".join(enc))

#Functiontodecode
def decode(key,clear):
    dec=[];
    for i in range(len(clear)):
        key_c = key[i%len(key)]
        dec_c=(ord(clear[i])-ord(key_c)+26)%26
        dec_c+=ord('A')
        dec.append(chr(dec_c))
    return ("".join(dec))

#Vermancipher
def ver_enc(key,clear):
    enc=[]
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = (ord(clear[i])-ord('A') + ord(key_c)-ord('A')) % 26
        enc_c += ord('A')
        enc.append(chr(enc_c))
    return ("".join(enc))

def ver_decode(key,clear):
    dec=[];
    for i in range(len(clear)):
        key_c = key[i%len(key)]
        dec_c=(ord(clear[i])-ord(key_c)+26)%26
        dec_c+=ord('A')
        dec.append(chr(dec_c))
    return ("".join(dec))

def Ref():
    clear=Msg.get();
    k=key.get()
    t=type.get()
    r=Result.get()
    if(t=="verman"):
        m=mode.get()
        if(m=="e"):
            Result.set(ver_enc(k,clear))
        elif(m=="d"):
            Result.set(ver_decode(k,clear))
    elif(t=="vigenere"):
        m = mode.get();
        if (m == 'e'):
            Result.set(encode(k,clear))
        elif (m == 'd'):
            Result.set(decode(k,clear))

# reference
lblReference = Label(f1, font=('arial', 16, 'bold'),
                     text="Name:", bd=16, anchor="w");

lblReference.grid(row=0, column=0);

txtReference = Entry(f1, font=('arial', 16, 'bold'),
                     textvariable=rand, bd=10, insertwidth=4,
                     bg="white", justify='right');

txtReference.grid(row=0, column=1);

# labels
lblMsg = Label(f1, font=('arial', 16, 'bold'),
               text="MESSAGE", bd=16, anchor="w");

lblMsg.grid(row=1, column=0);

txtMsg = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=Msg, bd=10, insertwidth=4,
               bg="white", justify='right');
txtMsg.grid(row=1, column=1);

lblkey = Label(f1, font=('arial', 16, 'bold'),
               text="KEY", bd=16, anchor="w");

lblkey.grid(row=2, column=0);

txtkey = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=key, bd=10, insertwidth=4,
               bg="white", justify='right');

txtkey.grid(row=2, column=1);


lblmode = Label(f1, font=('arial', 16, 'bold'),
                text="MODE(e for encrypt, d for decrypt)",
                bd=16, anchor="w");

lblmode.grid(row=3, column=0);

txtmode = Entry(f1, font=('arial', 16, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg="white", justify='right');

txtmode.grid(row=3, column=1);

lbltype=Label(f1,text="Type",font=('arial', 16, 'bold'),bd=16,anchor="w");
lbltype.grid(row=4,column=0);

type.set("vigenere")
drop=OptionMenu(f1,type,"vigenere","verman")

drop.grid(row=4,column=1,)


lblService = Label(f1, font=('arial', 16, 'bold'),
                   text="The Result-", bd=16, anchor="w");

lblService.grid(row=2, column=2);

txtService = Entry(f1, font=('arial', 16, 'bold'),
                   textvariable=Result, bd=10, insertwidth=4,
                   bg="white", justify='right');

txtService.grid(row=2, column=3);
#show message button
btnTotal = Button(f1, padx=16, pady=8, bd=16, fg="black",
                   font=('arial', 16, 'bold'), width=10,
                   text="Show Message", bg="yellow",command=Ref
                   ).grid(row=8, column=1);

# Reset button
btnReset = Button(f1, padx=16, pady=8, bd=16,
                  fg="black", font=('arial', 16, 'bold'),
                 width=10, text="Reset", bg="green",command=Reset
                  ).grid(row=8, column=2);

# Exit button
btnExit = Button(f1, padx=16, pady=8, bd=16,command=qExit,
                 fg="black", font=('arial', 16, 'bold'),
                  width=10, text="Exit", bg="red",
                  ).grid(row=8, column=3);

# keeps window alive
root.mainloop()