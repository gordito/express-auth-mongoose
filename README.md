# express-auth-mongoose

A quick way to implement a user account and authentication structure to your Express server.

Only supports MongoDB and Mongoose at the moment. Only single-factor authentication at the moment.

Featuring Create account, Login, Logout, Device sessions (cookies) and JWT.

Uses a JWT regular token and not a certificate.

## Installation and Example

1. Install the package
```
npm i express-auth-mongoose
```

2. Edit your `.env` file
Update your .env file with the `EXPRESS_AUTH_MONGODB` connection string if the default one is not correct for your setup.


3. Add Express Auth to code

```
const express = require('express');
const { AuthRouter, AuthMiddleware } = require('express-auth-mongoose');

const app = express();

// Adds all the paths to your backend
app.use('/auth', AuthRouter);

// Custom Path for when you're logged in
app.get('/userprofile', AuthMiddleware, (req, res) => {
  res.send(200).json(req.auth);
});

// Catch custom errors
app.use((err, req, res, next) => {
  if (err.code) {
    res.status(err.code).json({ error: err });
  } else {
    res.status(500).json({ error: err });
  }
});

const port = 8080;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);;
});
```

Thats about it, now you hopefully never need to write another user login/logout coce again.

## Endpoints / Paths

###  `POST /create-user`

Send body as a json with the following params:

```
username: Joi.string().required(),
password: Joi.string().min(8).required(),
usertype: Joi.string().default('email'),
```

### `POST /login`

Send body as a json with the following params:

```
username: Joi.string().required(),
password: Joi.string().required(),
```

### `GET /status`

Get login status, returns 200 and the User json object if user is loged in and have a valid session, else returns 401.


### `GET /logout`

Use query commands to target specific session or delete all user sessions.

Query params:
```
sessionId: Joi.string(),
all: Joi.boolean(),
```

### `POST /forgot-password`

Returns 200 regardless if the user is found or not. Function `onForgotPassword` contains token to email user.

Takes a json body as a json with the following params:

```
username: Joi.string().required(),
```

### `POST /restore-password`

Takes a json body as a json with the following params:

```
username: Joi.string().required(),
token: Joi.string().required(),
newpassword: Joi.string().min(8).required(),
```


## Module Exports

**AuthRouter**

The route for all Auth commands. Use this with express to expose all the auth endpoints.

**AuthMiddleware**

Middleware for verifying that the user is logged in.
Adds `req.auth` if there is a valid user session.

Put this middleware on all the routes you want to protect with a login.

**CustomError**

A simple class to throw custom http errors.

**UserModel**

The Mongoose model for the User, for querying the user DB.

**UserSessionModel**

The Mongoose model for the UserSession, for querying the user session DB.

**onLogin**

Post Login function, set this to a function to catch successfull login requests.

`onLogin(req, authUser)`
- req: the user login request
- authUser: the authenticated user object

Example:

```
const express = require('express');
const { AuthRouter, onLogin } = require('express-auth-mongoose');
const app = express();

// Adds all the paths to your backend
app.use('/auth', AuthRouter);

// Callback after login success
onLogin((req, userAuth) => {
  console.log('User Login Success', userAuth);
});

const port = 8080;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);;
});
```

**onLogout**

Post Logout function, set this to a function to catch successfull logout requests.

`onLogout(req, authUser)`
- req: the user logout request
- authUser: the authenticated user object

**onCreateUser**

Post Create User function, set this to a function to catch successfull create user requests.

`onCreateUser(req, newUser)`
- req: the user logout request
- authUser: the new user object

**onUserStatus**

Post User Status function, set this to a function to catch successfull user status requests.

`onUserStatus(req, authUser)`
- req: the user status request
- authUser: the authenticated user object

**onForgotPassword**

Post Forgot Password function, set this to a function to catch successfull retore token requests.

The token can be emailed to user to use as a 24h temporary restore token.

`onForgotPassword(req, userObj)`
- req: the forgot password request
- authUser: the user object including new token


**onRestorePassword**

Post Restore Password function, set this to a function to catch successfull retore password requests.

Not necessary to implement, but maybe you want to email user and inform that the password was updated after a successfull restore.

`onRestorePassword(req, userObj)`
- req: the restore password request
- authUser: the user object


## .env vars

If you intend to run this in production, you might want to change the .env varaiables.

**`EXPRESS_AUTH_MONGODB`**

MongoDB Connecton String eg. `mongodb://127.0.0.1:27017/myapp`

Default: `mongodb://127.0.0.1:27017/express-auth`

**`EXPRESS_AUTH_COOKIE_NAME`**

The name of the auth cookie that stores the client JWT.

Default: `express-auth-session`

**`EXPRESS_AUTH_JWT_SECRET`**

String used to encode the JWT secret. Change this in production.

Default: `donttellanyone`

**`EXPRESS_AUTH_DEBUG`**

Verbose - show all console logs from exceptions

Default: false


## Dependencies

This package uses some depenencies for validating input and building the Cookie and JWT

- Express - this package is intended for use with express
  - Express specific dependencies: cookie-parser
- Mongoose / MongoDB - If you use another DB we don't support it yet.
- Celebrate and Joi for input validation of username/password etc.
- jsonwebtoken - For generating and validating JWT
- dotenv - For ENV files support


## Roadmap and upcoming feature

Add issues or PR:s to the porject if you want to request features.

Current roadmap:
- Automatic testing of each release.
- User metadata and tracking, like saving IP of session and setting timezone and localization.
- Multi-factor authentication support.
- Restore password, inputing a email function like Sendgrid etc.
- Support for SQL databases like Postgres, MySQl and Sqlite.
- Option for not using cookies, eg. local storage instead.
- Add more login alternatives like Microsoft SSO.
