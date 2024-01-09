import concurrent.futures
from pymongo.errors import BulkWriteError
from db import DB

def stress_test_registration(db, username_prefix, num_accounts):
    def register_user(i):
        username = f"{username_prefix}_{i}"
        password = f"password{i}"
        try:
            db.register(username, password)
            print(f"Account {username} registered successfully.")
        except BulkWriteError as e:
            print(f"Error registering account {username}: {e.details['writeErrors'][0]['errmsg']}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(register_user, range(num_accounts))

def stress_test_login(db, username_prefix, num_accounts):
    def login_user(i):
        username = f"{username_prefix}_{i}"
        ip = f"192.168.1.{i}"
        tcp_port = 8000 + i
        udp_port = 9000 + i
        try:
            db.user_login(username, ip, tcp_port, udp_port)
            print(f"User {username} logged in successfully.")
        except BulkWriteError as e:
            print(f"Error logging in user {username}: {e.details['writeErrors'][0]['errmsg']}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(login_user, range(num_accounts))

def stress_test_is_account_exist(db, username_prefix, num_accounts):
    def check_account_exist(i):
        username = f"{username_prefix}_{i}"
        try:
            result = db.is_account_exist(username)
            print(f"User {username} exists: {result}")
        except Exception as e:
            print(f"Error checking account existence for {username}: {e}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(check_account_exist, range(num_accounts))

def stress_test_is_account_online(db, username_prefix, num_accounts):
    def check_account_online(i):
        username = f"{username_prefix}_{i}"
        try:
            result = db.is_account_online(username)
            print(f"User {username} is online: {result}")
        except Exception as e:
            print(f"Error checking account online status for {username}: {e}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(check_account_online, range(num_accounts))

def stress_test_user_logout(db, username_prefix, num_accounts):
    def logout_user(i):
        username = f"{username_prefix}_{i}"
        try:
            db.user_logout(username)
            print(f"User {username} logged out successfully.")
        except Exception as e:
            print(f"Error logging out user {username}: {e}")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(logout_user, range(num_accounts))

if __name__ == "__main__":
    # Adjust these values as needed
    num_accounts_to_create = 100
    username_prefix = "stress_test_user"

    # Initialize the database
    db = DB()

    # Run the stress test for registration
    stress_test_registration(db, username_prefix, num_accounts_to_create)

    # Run the stress test for user login
    stress_test_login(db, username_prefix, num_accounts_to_create)

    # Run the stress test for checking account existence
    stress_test_is_account_exist(db, username_prefix, num_accounts_to_create)

    # Run the stress test for checking account online status
    stress_test_is_account_online(db, username_prefix, num_accounts_to_create)

    # Run the stress test for user logout
    stress_test_user_logout(db, username_prefix, num_accounts_to_create)
