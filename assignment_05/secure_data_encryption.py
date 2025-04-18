import streamlit as st
import hashlib
from cryptography.fernet import Fernet
 
KEY = Fernet.generate_key()# Generate a key and cipher
cipher = Fernet(KEY)

# In-memory storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
#failed attemos
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
#user authorization
if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# Helper functions hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
#encrypting user data here with fernet
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()
#decrypt
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# User interface
st.title("🔐 Secure Data Encryption App (One Page)")

mode = st.radio("Choose an action:", ["Store Data", "Retrieve Data"])

if not st.session_state.authorized and mode != "Login":
    st.warning("🔒 Too many failed attempts. Please log in to continue.")
    mode = "Login"

if mode == "Store Data":
    st.subheader("📦 Store Data")
    text = st.text_area("Enter the text to encrypt")
    passkey = st.text_input("Create a passkey", type="password")
    if st.button("Encrypt & Store"):
        if text and passkey:
            encrypted = encrypt_data(text)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {"passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill in all fields.")

elif mode == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted = st.text_area("Paste your encrypted data")
    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Decrypt"):
        if encrypted and passkey:
            decrypted = decrypt_data(encrypted, passkey)
            if decrypted:
                st.success("✅ Data decrypted:")
                st.code(decrypted, language="text")
            else:#warning
                st.error(f"❌ Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")
                #logging out
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please provide all inputs.")

elif mode == "Login":
    st.subheader("🔐 Reauthorize to Continue")
    master = st.text_input("Enter master password", type="password")
    if st.button("Login"):
        if master == "admin123":
            st.success("✅ Logged in successfully!")
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
