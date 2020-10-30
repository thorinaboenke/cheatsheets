# Cheatsheet user authentication and authorization.
## Requirements
- **users table in the database** with columns username and password_hash. NEVER save plain text passwords anywhere.
- **csrf secret** saved in .env
- register page with form accepting username and password input. Serverside create a **csrf token** based on a secret, pass token via props. Submitting the form sends a **'POST' request** to the register api: username, password and token in the request body
- **api 'register'** , verifies csrf token against secret, hashes the password with **argon2** and saves the username and the password_hash in the database
- login page accepting username and password input
- **api 'login'** finds the username in the database and checks if password and password hash match
- protected routes: redirect when a non logged in user tries to access a restricted page

## Libraries
argon2: create a hash from a password, save the password hash in the users table. On login, veryfy the password against the hash. 

hash() and verify() return a promise.
```node.js
const hash = await argon2.hash(password) //creates a hash from a password
argon2.verify(hash, password) // verify a password against a hash
```
csrf: create and save a secret in environment variable, generate tokens serverside based on that secret (on every page refresh), pass the token via props, send the token along with the registration request, have the registration handler verify the csrf token against the secret
```node.js
const Tokens = require('csrf')
const tokens = new Tokens()
const secret = tokens.secretSync() // creates a secret, save in .env file: CSRF_TOKEN_SECRET = xxxxxxxxxxxx
const token = tokens.create(secret) // creates a token based on the secret
const isVerified = tokens.verify( secret, token)

// in getServerSideProps:
const Tokens = (await import('csrf')).default;
const secret = process.env.CSRF_TOKEN_SECRET
if (typeof secret === 'undefined') {
throw new Error ('CSRF_TOKEN_SECRET environment variable is undefined') }
const token = tokens.create(secret)

ret

```
crypto
```node.js

```
cookie
```node.js

```
next-cookie
```node.js

```


## hash function
Does not run client side to prevent reverse engeneering
## requests to register and login endpoint:
Method: 'POST', A 'GET' request would put the information in the URL, then the password would be visible
## to redirect from pages
new in Next 10: serverSideProps can return 'redirect', which re-routes the request to that page
## csrf token
generated by the server when login successful, stored in a cookie client side



```javascript

```


```javascript
//migration file to create users table
exports.up = async (sql) => {
  await sql`
  CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    username VARCHAR(40) NOT NULL,
    password_hash VARCHAR(100) NOT NULL
);
  `;
};

exports.down = async (sql) => {
  await sql`
  DROP TABLE IF EXISTS users;`;
};
```

```javascript
//migration file to create sessions table
exports.up = async (sql) => {
  await sql`CREATE TABLE IF NOT EXISTS sessions (
		session_id INTEGER PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
		token VARCHAR(32),
		expiry_timestamp TIMESTAMP NOT NULL DEFAULT NOW()+ INTERVAL '24 hours',
		user_id INTEGER NOT NULL REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE);`;
};

exports.down = async (sql) => {
  await sql`DROP TABLE IF EXISTS sessions;`;
};

```
The token (a string of random characters) is created with the crypto library (included with node.js), the expiry timestamp is set to the current date + 24 hours so the token will expire after 24 h. The user_id references a user id in the user table. In case this user gets deleted or updated also the corresponding entries in the sessions table will be deleted or updated (CASCADE).
