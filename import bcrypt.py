import bcrypt

print("1. Generate salt hash nad check password: ")
print("2. Exit Program: ")

while True:
    user_choice = input("Choose a option: ")

    if user_choice == "1":
        input_user = input("Enter your username: ")
        input_passwd = input("Enter your password: ")

        password = input_passwd.encode('utf-8')

        hashedPassword = bcrypt.hashpw(password, bcrypt.gensalt())
        print("The salt password is: ", hashedPassword)

        check = input("check password: ")

        check = check.encode('utf-8')

        if bcrypt.checkpw(check, hashedPassword):
            print("login success")
        else:
            print("Incorrect password")

    elif user_choice == "2":
        print("Quitting the Program...")
        break

    else:
        print("Please choose a correct option")