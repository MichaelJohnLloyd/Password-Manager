

'''We’re using Python 3. Any version above 3.6 is fine as we’re going to make use of F strings. Also, to copy our retrieved password to our clipboard, we’ll make use of the pyperclip module. To install, open up your command prompt (or terminal) and run:'''

import json, hashlib, getpass, os, pyperclip, sys
from cryptography.fernet import Fernet

'''json is a library for encoding and decoding JSON (JavaScript Object Notation) data, commonly used for data serialization and interchange.

hashlib is a library that provides secure hash functions, including SHA-256, for creating hash values from data, often used for password hashing and data integrity verification. You can check this tutorial on how to use it.

getpass: A library for safely and interactively entering sensitive information like passwords without displaying the input on the screen. Similar to the way the Linux terminals are.

os: A library for interacting with the operating system, allowing you to perform tasks like file and directory manipulation.

pyperclip: A library for clipboard operations, enabling you to programmatically copy and paste text to and from the clipboard in a platform-independent way.

sys: This module is a built-in Python module that provides access to various system-specific parameters and functions.

cryptography.fernet: Part of the cryptography library, it provides the Fernet symmetric-key encryption method for securely encrypting and decrypting data. You can check this tutorial for more info.

After importing the necessary libraries, we create a function for hashing. This function would be used to hash our master password upon registration:'''

# Function for Hashing the Master Password.
def hash_password(password):
   sha256 = hashlib.sha256()
   sha256.update(password.encode())
   return sha256.hexdigest()
   
'''After that, we create a function for generating a key. This key would be used to encrypt our passwords upon adding, and decrypt upon retrieval. Please bear in mind that only the key we used to encrypt our passwords, can be used to decrypt it. If you use another, you’ll get errors. I’m saying this because this is a function and anytime it gets executed (you call it), it generates a new key. This is worth noting in case you want to use the function in another program. In this program, we generate it once, store it, and keep using it, so you have nothing to worry about.

Next up, we fernet the key (making it able to encrypt and decrypt our passwords) and create functions for encrypting and decrypting:'''
   
   # Generate a secret key. This should be done only once as you'll see.
def generate_key():
   return Fernet.generate_key()

# Initialize Fernet cipher with the provided key.
def initialize_cipher(key):
   return Fernet(key)

# Function to encrypt a  password.
def encrypt_password(cipher, password):
   return cipher.encrypt(password.encode()).decode()

# Function to decrypt a  password.
def decrypt_password(cipher, encrypted_password):
   return cipher.decrypt(encrypted_password.encode()).decode()
   
'''After that, we create a function for owner registration. 
Saving credentials in the user_data.json file. 
Remember, we’ll be hashing the password. This is the master password. The keys to the kingdom:'''
   
   # Function to register you.
def register(username, master_password):
   # Encrypt the master password before storing it
   hashed_master_password = hash_password(master_password)
   user_data = {'username': username, 'master_password': hashed_master_password}
   file_name = 'user_data.json'
   if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
       with open(file_name, 'w') as file:
           json.dump(user_data, file)
           print("\n[+] Registration complete!!\n")
   else:
       with open(file_name, 'x') as file:
           json.dump(user_data, file)
           print("\n[+] Registration complete!!\n")
           
'''Next up, we create a function for logging a user in. 
It accepts a username and password from a user, it then hashes the password entered by the user. 
If the hash of the entered password is the same as the hash of the saved password (in the JSON file) and the usernames are also the same, it grants access. 
Otherwise, you know the rest. This is how password-cracking processes take place.

In secure systems, passwords are stored as hashes and not plain texts. 
So attackers keep trying the hashes of different known passwords in the hope of gaining access to the system. 
This is why we are advised to use strong, unique passwords:'''

# Function to log you in.
def login(username, entered_password):
   try:
       with open('user_data.json', 'r') as file:
           user_data = json.load(file)
       stored_password_hash = user_data.get('master_password')
       entered_password_hash = hash_password(entered_password)
       if entered_password_hash == stored_password_hash and username == user_data.get('username'):
           print("\n[+] Login Successful..\n")
       else:
           print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")
           sys.exit()
   except Exception:
       print("\n[-] You have not registered. Please do that.\n")
       sys.exit()
       
'''Next is a function to view websites saved in our password manager. 
Remember that the order in which functions are written doesn’t really matter. 
It’s the calling that matters:'''

# Function to view saved websites.
def view_websites():
   try:
       with open('passwords.json', 'r') as data:
           view = json.load(data)
           print("\nWebsites you saved...\n")
           for x in view:
               print(x['website'])
           print('\n')
   except FileNotFoundError:
       print("\n[-] You have not saved any passwords!\n")
       
'''Next up, we generate or load our key. If it’s the first time, we generate and save our key. Otherwise, we just load it:'''

# Load or generate the encryption key.
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
   with open(key_filename, 'rb') as key_file:
       key = key_file.read()
else:
   key = generate_key()
   with open(key_filename, 'wb') as key_file:
       key_file.write(key)

cipher = initialize_cipher(key)

'''Basically, this function checks if an encryption_key.key file exists. 
If it does, it loads it for use. If it doesn’t, it creates it and saves our unique key in it. 
If it exists, it means it isn’t our first time running the program so it just loads our unique key. 
This key is the heart of this program. You want to make sure you keep it safe. 

Now let's make a function to add passwords:'''

# Function to add (save password).
def add_password(website, username1, password):
   # Check if passwords.json exists
   if not os.path.exists('passwords.json'):
       # If passwords.json doesn't exist, initialize it with an empty list
       data = []
   else:
       # Load existing data from passwords.json
       try:
           with open('passwords.json', 'r') as file:
               data = json.load(file)
       except json.JSONDecodeError:
           # Handle the case where passwords.json is empty or invalid JSON.
           data = []
   # Encrypt the password
   encrypted_password = encrypt_password(cipher, password)
   # Create a dictionary to store the website and password
   password_entry = {'website': website, 'username': username1, 'password': encrypted_password}
   data.append(password_entry)
   # Save the updated list back to passwords.json
   with open('passwords.json', 'w') as file:
       json.dump(data, file, indent=4)
       
'''Here, we encrypt the passwords and save them in our JSON file.

Let's create a function to retrieve a saved password:'''

# Function to retrieve a saved password.
def get_password(website):
   # Check if passwords.json exists
   if not os.path.exists('passwords.json'):
       return None
   # Load existing data from passwords.json
   try:
       with open('passwords.json', 'r') as file:
           data = json.load(file)
   except json.JSONDecodeError:
       data = []
   # Loop through all the websites and check if the requested website exists.
   for entry in data:
       if entry['website'] == website:
           # Decrypt and return the password
           decrypted_password = decrypt_password(cipher, entry['password'])
           return decrypted_password
   return None
   
'''This function takes in the website as a parameter and returns the decrypted password to the user (us).

Finally the body of the program. Option displays and function calling according to the user’s input:'''

# Infinite loop to keep the program running until the user chooses to quit.
while True:
   print("1. Register")
   print("2. Login")
   print("3. Quit")
   choice = input("Enter your choice: ")
   if choice == '1':  # If a user wants to register
       file = 'user_data.json'
       if os.path.exists(file) and os.path.getsize(file) != 0:
           print("\n[-] Master user already exists!!")
           sys.exit()
       else:
           username = input("Enter your username: ")
           master_password = getpass.getpass("Enter your master password: ")
           register(username, master_password)
   elif choice == '2':  # If a User wants to log in
       file = 'user_data.json'
       if os.path.exists(file):
           username = input("Enter your username: ")
           master_password = getpass.getpass("Enter your master password: ")
           login(username, master_password)
       else:
           print("\n[-] You have not registered. Please do that.\n")
           sys.exit()
       # Various options after a successful Login.
       while True:
           print("1. Add Password")
           print("2. Get Password")
           print("3. View Saved websites")
           print("4. Quit")
           password_choice = input("Enter your choice: ")
           if password_choice == '1':  # If a user wants to add a password
               website = input("Enter website: ")
               username1 = input("Enter Username: ")
               password = getpass.getpass("Enter password: ")
               # Encrypt and add the password
               add_password(website, username1, password)
               print("\n[+] Password added!\n")
           elif password_choice == '2':  # If a User wants to retrieve a password
               website = input("Enter website: ")
               decrypted_password = get_password(website)
               if website and decrypted_password:
                   # Copy password to clipboard for convenience
                   pyperclip.copy(decrypted_password)
                   print(f"\n[+] Username for {website}: {username1}\n[+] Password for {website}: {decrypted_password}\n[+] Password copied to clipboard.\n")
               else:
                   print("\n[-] Password not found! Did you save the password?"
                         "\n[-] Use option 3 to see the websites you saved.\n")
           elif password_choice == '3':  # If a user wants to view saved websites
               view_websites()
           elif password_choice == '4':  # If a user wants to quit the password manager
               break
   elif choice == '3':  # If a user wants to quit the program
       break