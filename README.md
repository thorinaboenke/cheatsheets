# Cheatsheet user authentication and authorization.
## Requirements
- **users table in the database** with columns username and password_hash. NEVER save plain text passwords anywhere.
- **csrf secret** saved as environment variable in .env file
- register page with form accepting username and password input. Serverside create a **csrf token** based on the csrf secret, pass token via props. Submitting the form sends a **'POST' request** to the register api: username, password and token in the request body
- **api 'register'** , verifies csrf token against secret, checks if the username alrady exists, if it already exists, sends back 403 status, if not, hashes the password with **argon2** and saves the username and the password_hash in the database
- login page accepting username and password input
- **api 'login'** tries to find the username in the database and checks if password and password hash match, 

- protected routes: redirect when a non logged in user tries to access a restricted page

## Libraries
### argon2
create a hash from a password, save the password hash in the users table. On login, verify the entered password against the hash. 
NEVER send plain text password via GET requests (would be visible in the url)

hash() and verify() return a promise.
```node.js
const hash = await argon2.hash(password) //creates a hash from a password
const isVerified = await argon2.verify(hash, password) //verify a password against a hash
```
### csrf
create and save a secret in environment variable, generate tokens serverside based on that secret (on every page refresh), pass the token via props, send the token along with the registration request, have the registration handler verify the csrf token against the secret
```node.js
const Tokens = require('csrf') // import library
const tokens = new Tokens() // new Token instance
const secret = tokens.secretSync() // creates a secret, save this one in .env file: CSRF_TOKEN_SECRET = xxxxxxxxxxxx
const token = tokens.create(secret) // creates a token based on the secret
const isVerified = tokens.verify(secret, token) // verifies a token against a secret

// in getServerSideProps:
export async function getServerSideProps(context) {
const Tokens = (await import('csrf')).default;
const secret = process.env.CSRF_TOKEN_SECRET // gets the secret from the environment variable file
if (typeof secret === 'undefined') {
throw new Error ('CSRF_TOKEN_SECRET environment variable is undefined') }
const token = tokens.create(secret)
// check if a secret is defined, if yes, create token based on the secret that gets passed to the page

  return { props: { token } };
}

```
### crypto
```node.js

```
### cookie
```node.js

```
### next-cookie
This library is used server side to get the token from the cookies (passed to serverSideProps as context
```node.js
export async function getServerSideProps(context) {
const { session: token } = nextCookies(context);
```

### login API route
```node.js
import argon2 from 'argon2';
import Tokens from 'csrf';
import {
  getUserByUsername,
  registerUser,
} from '../../util/database';
const tokens = new Tokens();

export default async function handler(request, response) {
const { username, password, token } = request.body;

  //1) get the secret from the .env file
  const secret = process.env.CSRF_TOKEN_SECRET;
  //2) check if the secret is configured, if not send back a 500 status
  if (typeof secret === 'undefined') {
    console.error('CSRF_TOKEN_SECRET environment variable not configured');
    return response.status(500).send({ success: false });
  }
  //3)check the submitted token against the secret
  const verified = tokens.verify(secret, token);
  // if not verified, send back 401 status (unauthorized)
  if (!verified) {
    return response.status(401).send({
      success: false,
      errors: [
        {
          message: 'invalid token',
        },
      ],
    });
  }

  // check if there is already a user in the database with that username
  const usernameAlreadyTaken =
    typeof (await getUserByUsername(username)) !== 'undefined';

  if (usernameAlreadyTaken) {
    // HTTP status code: 409 Conflict
    return response.status(409).send({
      success: false,
      errors: [
        {
          message: 'Username already taken',
          field: 'user',
        },
      ],
    });
  }
  // create a hashed version of the password with argon2 and register user in database
  try {
    const passwordHash = await argon2.hash(password);
    await registerUser(username, passwordHash);
  } catch (err) {
    return response.status(501).send({ answer: 4, success: false });
  }

  response.send({ success: true });
}
```

## hash function
Does not run client side to prevent reverse engeneering
## requests to register and login endpoint:
Method: 'POST', A 'GET' request would put the information in the URL, then the password would be visible
## to redirect from pages
new in Next.js 10: serverSideProps can return 'redirect', which re-routes the request to that page
## csrf token
generated by the server when login successful, stored in a cookie client side and saved in the database sessions table with an expiry date 24h in the future



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
The token (a string of random characters) is created with the crypto library (included with node.js), the expiry timestamp is set to the current date + 24 hours so the token will expire after 24 h. The user_id references a user id in the user table. In case this user gets deleted or updated also the corresponding entries in the sessions table will be deleted or updated (this is what CASCADE does).
