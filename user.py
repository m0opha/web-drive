import sqlite3

class UserDatabase:

    def __init__(self, dbPath):
        self.dbPath = dbPath

    def getConnection(self):
        return sqlite3.connect(self.dbPath)

    def getUser(self, username):
        with self.getConnection() as conn:
            cursor = conn.execute(
                """
                SELECT username, password
                FROM users
                WHERE username = ?
                """,
                (username,)
            )

            row = cursor.fetchone()

            if row is None:
                return None

            return {
                "username": row[0],
                "password": row[1]
            }

    def getPassword(self, username):
        user = self.getUser(username)

        if user is None:
            return None

        return user["password"]

    def userExists(self, username):
        return self.getUser(username) is not None

    def updatePassword(self, username, new_hash):
        with self.getConnection() as conn:
            conn.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (new_hash, username)
            )
            conn.commit()
