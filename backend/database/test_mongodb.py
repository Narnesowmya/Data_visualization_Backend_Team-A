from mongodb import test_connection

try:
    if test_connection():
        print("MongoDB connection successful!")
except Exception as e:
    print("MongoDB connection failed!")
    print("Error:", e)