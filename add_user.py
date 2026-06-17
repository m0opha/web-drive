from dotenv import load_dotenv
import sqlite3
import bcrypt
import os
import sys

load_dotenv()

_DB_NAME = os.getenv('DB')



def startdb():
    conn = sqlite3.connect(_DB_NAME)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def createUser(username:str, password:str):
    passwordHash = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    conn = sqlite3.connect(_DB_NAME)

    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, passwordHash)
    )

    conn.commit()
    conn.close()

def changePassword(username: str, new_password: str):
    passwordHash = bcrypt.hashpw(
        new_password.encode(),
        bcrypt.gensalt()
    ).decode()
    conn = sqlite3.connect(_DB_NAME)
    conn.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (passwordHash, username)
    )
    conn.commit()
    conn.close()
    print(f"Password changed for {username}")

def main():
    if not os.path.exists(os.path.join(".", _DB_NAME)):
        startdb()

    print("1. Add user")
    print("2. Change password")
    op = input("> ")

    if op == "1":
        username = input("Username: ")
        password = input("Password: ")
        createUser(username=username, password=password)

    elif op == "2":
        username = input("Username: ")
        new_password = input("New password: ")
        changePassword(username=username, new_password=new_password)
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        pass
    
