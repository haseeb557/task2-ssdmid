import sqlite3
import bcrypt

# Admin credentials (hashed)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt())

# Connect to the SQLite database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create the users table if it doesn't exist
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)")
conn.commit()

# Function to authenticate user
def authenticate(username, password):
    try:
        # Use parameterized query to prevent SQL injection
        query = "SELECT password_hash FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        if user:
            # Check if the entered password matches the stored hash
            stored_hash = user[0]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                if username == ADMIN_USERNAME and bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH):
                    print("Admin login successful!")
                    return True
                else:
                    print("User login successful!")
                    return True
            else:
                print("Invalid password!")
                return False
        else:
            print("Username not found!")
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.commit()

# Function to register a new user
def register_user(username, password):
    try:
        if len(username) > 255 or len(password) > 255:
            print("Input too long!")
            return
        
        # Validate password strength
        if len(password) < 8:
            print("Password too short. Minimum 8 characters required.")
            return
        
        # Hash the password before storing it
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Use parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        print("User registered successfully!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")

# Main logic
def main():
    print("1. Register\n2. Login")
    choice = input("Enter choice: ")

    if choice == "1":
        user = input("Enter username: ")
        pwd = input("Enter password: ")
        register_user(user, pwd)
    elif choice == "2":
        user = input("Enter username: ")
        pwd = input("Enter password: ")
        authenticate(user, pwd)
    else:
        print("Invalid choice!")

# Call main logic and ensure database connection is closed after usage
try:
    main()
finally:
    conn.close()
