from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import codecs
import base64 


def encryptData(plaintext, key):
    key = key.encode('utf-8')
    plaintext = pad(plaintext.encode(),16)

    cipher = AES.new(key,AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext)

def encryptAction():

    if len(pass_field.get()) != 16:
        messagebox.showwarning(title=None, message="Password must 16 char")
    else :
        ciphertext = encryptData(plain_field.get("1.0",END),KEY.get())
        ciphertext = ciphertext.decode("utf-8", "ignore")

        cipher_field.delete(1.0,"end")
        cipher_field.insert(1.0, ciphertext)

def decryptData(ciphertext, key):
    key = key.encode()
    ciphertext = base64.b64decode(ciphertext)

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = cipher.decrypt(ciphertext)
    
    return unpad(cipher.decrypt(ciphertext),16)

def decryptAction():
    if len(pass_field.get()) != 16:
        messagebox.showwarning(title=None, message="Password must 16 char")
    else :
        ciphertext = cipher_field.get("1.0",END)
        ciphertext.encode()
        plaintext = decryptData(ciphertext,KEY.get())
        plaintext = plaintext.decode("utf-8", "ignore")

        plain_field.delete(1.0,"end")
        plain_field.insert(1.0, plaintext)

 
# Driver code
if __name__ == "__main__":
     
    # create a GUI window
    root = Tk()
 
    # set the title of GUI window
    root.title("Text Encryption")

    KEY = StringVar()
 
    # set the configuration of GUI window
    # root.geometry("700x600")
 
    # LABEL WIDGET
    heading = Label(root, text="Enkripsi Text AES CBC")
    plaintextLabel = Label(root, text="Plaintext :")
    passwordLabel = Label(root, text="Password :")
    ciphertextLabel = Label(root, text="Ciphertext :")

    heading.grid(row=0, column=1,padx=(10,10),pady=(10,10))
    plaintextLabel.grid(row=1, column=0,padx=(10,10))
    passwordLabel.grid(row=2, column=0,padx=(10,10))
    ciphertextLabel.grid(row=3, column=0,padx=(10,10))
 
    #INPUT WIDGET
    plain_field = Text(root,width=15,height=15)
    pass_field = Entry(root, textvariable=KEY)
    cipher_field = Text(root,width=15,height=15)

    plain_field.grid(row=1, column=1, ipadx="200",ipady="5",pady=5,padx=5)
    pass_field.grid(row=2, column=1, ipadx="200",ipady="5",pady=5,padx=5)
    cipher_field.grid(row=3, column=1, ipadx="200",ipady="5",pady=5,padx=5)

    
    # pass_field.trace("w", lambda *args: character_limit(pass_field))
    # if len(pass_field.get()) > 16:
    #     pass_field.delete(16, END)

    # print(pass_field.get())

    #BUTTON WIDGET
    buttonEncrypt = Button(root,text="Encrypt",command=encryptAction)
    buttonDecrypt = Button(root,text="Decrypt",command=decryptAction)

    buttonEncrypt.grid(row=5,column=1,pady=10,padx=10)
    buttonDecrypt.grid(row=5,column=1,pady=10,padx=10,sticky="e")

 
    #GET STRING FROM FORM

 
    # start the GUI
    root.mainloop()