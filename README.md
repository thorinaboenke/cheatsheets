# Cheatsheet user authentication an authorization.

- users table in the databse with columns username and password_hash (and more information)
- register page accepting username and password input
- api 'register' handler, which hashes the password and saves the username and the password_hash in the database
- login pageaccepting username and password input
- api 'register' handler that checks for the username in the database and checks if password and password hash match
- 
