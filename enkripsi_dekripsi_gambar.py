from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import base64
import os


def encrypt_data(plaintext, key):
    key = key.encode('utf-8')
    plaintext = pad(plaintext,16)

    cipher = AES.new(key,AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(ciphertext)

def encrypt_action():

    if len(pass_field.get()) != 16:
        messagebox.showwarning(title=None, message="Password must 16 char")
    else :
        if len(file_dir_field.get())!= 0:
            file_dir = file_dir_field.get()

            with open(file_dir,'rb') as imageFile:
                original_file = imageFile.read()
                print(type(original_file))
            
                ciphertext = encrypt_data(original_file,KEY.get())

                with open('encrypted_'+os.path.basename(file_dir),'wb') as encrypted_file:
                    encrypted_file.write(ciphertext)

                result_field.delete(1.0,"end")
                result_field.insert(1.0, 'Encrypted Success')

def decrypt_data(ciphertext, key):
    key = key.encode()
    ciphertext = base64.b64decode(ciphertext)

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = cipher.decrypt(ciphertext)
    
    return unpad(cipher.decrypt(ciphertext),16)

def decrypt_action():
    if len(pass_field.get()) != 16:
        messagebox.showwarning(title=None, message="Password must 16 char")
    else :
        if len(file_dir_field.get())!= 0:
            file_dir = file_dir_field.get()

            with open(file_dir,'rb') as encrypted_file:
                ciphertext = encrypted_file.read()

                print(type(ciphertext))

                plaintext = decrypt_data(ciphertext,KEY.get())

                new_file_name = os.path.basename(file_dir)
                new_file_name = new_file_name.lstrip('encrypted_')

                with open('decrypted_'+new_file_name,'wb') as decrypted_file:
                    decrypted_file.write(plaintext)

                result_field.delete(1.0,"end")
                result_field.insert(1.0, 'Decrypted Success')

def select_file():
    filetypes = (
        ('image file', '*.png'),
        ('image file', '*.jpg'),
        ('All files', '*.*')
    )

    filename = filedialog.askopenfilename(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes)

    file_dir_field.delete(0,END)
    file_dir_field.insert(0,filename)

    return filename


# Driver code
if __name__ == "__main__":
     
    # create a GUI window
    root = Tk()
 
    # set the title of GUI window
    root.title("Image Encryption")

    KEY = StringVar()
 
    # set the configuration of GUI window
    # root.geometry("700x600")
 
    # LABEL WIDGET
    heading = Label(root, text="Enkripsi Gambar AES EBC")
    file_label = Label(root, text="File :")
    file_dir_label = Label(root, text="File Directory :")
    password_label = Label(root, text="Password :")
    result_label = Label(root, text="Result :")

    heading.grid(row=0, column=1,padx=(10,10),pady=(10,10))
    file_label.grid(row=1, column=0)
    file_dir_label.grid(row=2, column=0,padx=(10,10),sticky="w")
    password_label.grid(row=3, column=0,padx=(10,10),sticky="w")
    result_label.grid(row=4, column=0,padx=(10,10),sticky="w")
 
    #INPUT WIDGET
    buttonForOpenFile = Button(root,text="Open File",command=select_file)
    file_dir_field = Entry(root)
    pass_field = Entry(root, textvariable=KEY)
    result_field = Text(root,width=15,height=5)

    buttonForOpenFile.grid(row=1, column=1,sticky="s")
    file_dir_field.grid(row=2, column=1, ipadx="200",ipady="5",pady=5,padx=5)
    pass_field.grid(row=3, column=1, ipadx="200",ipady="5",pady=5,padx=5)
    result_field.grid(row=4, column=1, ipadx="200",ipady="5",pady=5,padx=5)

    #BUTTON WIDGET
    button_encrypt = Button(root,text="Encrypt",command=encrypt_action)
    button_decrypt = Button(root,text="Decrypt",command=decrypt_action)

    button_encrypt.grid(row=6,column=1,pady=10,padx=10)
    button_decrypt.grid(row=6,column=1,pady=10,padx=10,sticky="e")


    # start the GUI
    root.mainloop()
