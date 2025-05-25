import streamlit as st
import hashlib
from cryptography.fernet import Fernet

import base64

# In-memory storage for user data
stored_data = {}
failed_attempts = {}

# Function to hash passkeys using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to generate a Fernet key from the passkey
def generate_key(passkey):
    # Ensure the key is 32 bytes
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key)

# Function to encrypt data
def encrypt_data(data, passkey):
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

# Function to decrypt data
def decrypt_data(token, passkey):
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(token.encode()).decode()

# Streamlit application
def main():
    st.title("🔐 Secure Data Encryption System")

    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("Welcome to the Secure Data Encryption System")
        st.write("Use the sidebar to navigate through the application.")

    elif choice == "Store Data":
        st.subheader("Store New Data")
        user_id = st.text_input("Enter a unique identifier (e.g., username):")
        data = st.text_area("Enter the data to encrypt:")
        passkey = st.text_input("Enter a passkey:", type="password")

        if st.button("Encrypt and Store"):
            if user_id in stored_data:
                st.warning("Identifier already exists. Choose a different one.")
            else:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(data, passkey)
                stored_data[user_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                failed_attempts[user_id] = 0
                st.success("Data encrypted and stored successfully.")

    elif choice == "Retrieve Data":
        st.subheader("Retrieve Stored Data")
        user_id = st.text_input("Enter your identifier:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt and Retrieve"):
            if user_id in stored_data:
                if failed_attempts.get(user_id, 0) >= 3:
                    st.error("Maximum failed attempts reached. Please reauthorize.")
                    st.info("Redirecting to Login page...")
                    st.experimental_rerun()
                else:
                    hashed_input = hash_passkey(passkey)
                    if hashed_input == stored_data[user_id]["passkey"]:
                        decrypted_text = decrypt_data(stored_data[user_id]["encrypted_text"], passkey)
                        st.success("Data decrypted successfully:")
                        st.write(decrypted_text)
                        failed_attempts[user_id] = 0  # Reset failed attempts
                    else:
                        failed_attempts[user_id] += 1
                        attempts_left = 3 - failed_attempts[user_id]
                        st.error(f"Incorrect passkey. Attempts left: {attempts_left}")
            else:
                st.warning("Identifier not found.")

    elif choice == "Login":
        st.subheader("Reauthorization Required")
        user_id = st.text_input("Enter your identifier:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Reauthorize"):
            if user_id in stored_data:
                hashed_input = hash_passkey(passkey)
                if hashed_input == stored_data[user_id]["passkey"]:
                    failed_attempts[user_id] = 0
                    st.success("Reauthorization successful. You can now retrieve your data.")
                else:
                    st.error("Incorrect passkey.")
            else:
                st.warning("Identifier not found.")

if __name__ == "__main__":
    main()
