import hashlib
import streamlit as st

def hash_password(password, algorithm='md5'):
    """Encrypt the password using the specified algorithm."""
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm")

def generate_combinations(charset, length):
    """Manually generate all possible combinations of a given length."""
    if length == 1:
        for char in charset:
            yield char
    else:
        for char in charset:
            for sub_comb in generate_combinations(charset, length - 1):
                yield char + sub_comb

def brute_force_crack(hashed_password):
    """Try common hash algorithms to find the original password."""
    charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    max_length = 6  # Adjust based on expected password length
    for length in range(1, max_length + 1):
        for attempt_password in generate_combinations(charset, length):
            for algo in ['md5', 'sha256', 'sha1', 'sha512']:
                if hash_password(attempt_password, algo) == hashed_password:
                    return attempt_password, algo
    return None, None

st.title("Hashed Password Converter")

option = st.radio("Choose an option:", ["Hash Password", "Decrypt Hash"])

if option == "Hash Password":
    password = st.text_input("Enter password:", type="password")
    algorithm = st.selectbox("Select Hashing Algorithm", ["md5", "sha256", "sha1", "sha512"])
    if st.button("Generate Hash"):
        hashed = hash_password(password, algorithm)
        st.success(f"Hashed Password ({algorithm}): {hashed}")

elif option == "Decrypt Hash":
    hashed_password = st.text_input("Enter hashed password:")
    if st.button("Find Original Password"):
        result, algo = brute_force_crack(hashed_password)
        if result:
            st.success(f"Original Password: {result} (Algorithm: {algo})")
        else:
            st.error("Password not found")
