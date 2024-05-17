const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy

const sqlite3 = require('better-sqlite3');
// -------- oauth optional
const dotenv = require('dotenv')
dotenv.config()
const axios = require('axios')

// --------- OIDC
const session = require('express-session')

const { Issuer, Strategy: OpenIDConnectStrategy } = require('openid-client')

//-----------------------
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 

//----------------------
// encryption config
const scryptPbkdf = require('scrypt-pbkdf')
const scryptCODEC = require('base64-arraybuffer')

const global_salt = scryptPbkdf.salt(32)
const scryptParams = {
  N: 16384, //2097152  //16384
  r: 8,
  p: 2
}
const derivedKeyLength = 32

//----------------------

const port = 3000
let sql;


//connect to DB
const db = new sqlite3("./test.db", {"fileMustExist": true})
/*
//create table :
sql = `CREATE TABLE users (id INTEGER PRIMARY KEY, username, password)`;
db.run(sql);
*/

// //drop table :
// db.run("DROP TABLE users");

//insert data into table :

async function key_func(pass, salt){
	const password = pass
	const key_array_buffer = await scryptPbkdf.scrypt(password, salt, derivedKeyLength, scryptParams)
	const key = scryptCODEC.encode(key_array_buffer)
	return key
}

async function change_salt(salt, flag){
	let new_salt = null;
	if (flag){
		new_salt = scryptCODEC.decode(salt); //returns an object array that we must use to generate the key
	}
	else{
		new_salt = scryptCODEC.encode(salt); //returns a string that we can store in the DB
	}
	return new_salt
}

async function getIDfromuser(db, username) {
        sql = `SELECT * FROM users WHERE username=?`;
        return db.prepare(sql).all(username)
}

async function get_info_from_user(db, userID) {
        sql = `SELECT * FROM users WHERE id=?`;
        return db.prepare(sql).all(userID)
}

async function func(username) {
	await new Promise(r => setTimeout(r, 1000))
	console.log("-----------")
	user = await getIDfromuser(db, username)
	user_info = await get_info_from_user(db, user[0].id)
	//console.log(user[0].id)
	//console.log(user_info[0].password)
	return user_info
}

async function create_JWT(req, res, user_email='user@email.com', oauth=false) {

	// This is what ends up in our JWT
	let jwtClaims = {};
	if (oauth){
		jwtClaims = {
			sub: user_email,
			iss: 'localhost:3000',
			aud: 'localhost:3000',
			exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
			role: 'user' ,// just to show a private JWT field
			examiner: true
		}
	}
	else{
		if (req.user.username === 'alanis'){
			jwtClaims = {
			sub: req.user.username,
			iss: 'localhost:3000',
			aud: 'localhost:3000',
			exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
			role: 'user' ,// just to show a private JWT field
			examiner: true
		}
		}
		else{
			jwtClaims = {
			sub: req.user.username,
			iss: 'localhost:3000',
			aud: 'localhost:3000',
			exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
			role: 'user' // just to show a private JWT field
			}
		}
	}

	// generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
	const token = jwt.sign(jwtClaims, jwtSecret)

	// From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
	res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
	res.redirect('/')

	// And let us log a link to the jwt.io debugger for easy checking/verifying:
	console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
	console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)

}

async function main () {
  	const app = express()
	app.use(logger('dev'))
	app.use(session({
	    secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
	    resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
	    saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
	  }))
	  
	/*
	Configure the local strategy for using it in Passport.
	The local strategy requires a `verify` function which receives the credentials
	(`username` and `password`) submitted by the user.  The function must verify
	that the username and password are correct and then invoke `done` with a user
	object, which will be set at `req.user` in route handlers after authentication.
	*/
	passport.use('username-password', new LocalStrategy(
	  {
	    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
	    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
	    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
	  },
	  async function (username, password, done) {
	    info = await func(username)
	    old_salt = await change_salt(info[0].salt, true) //used to be true
	    key_result = await key_func(password, old_salt) //old_salt
	    //new_salt = await change_salt(global_salt, false)
	    console.log(info)
	    console.log(key_result)
	    //old_salt = await change_salt(info[0].salt, false)
	    //console.log(old_salt)
	    
	    if (username === info[0].username && key_result === info[0].password) {
	      const user = { 
		username: username,
		description: 'the only user that deserves to get to this server'
	      }
	      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
	    }
	    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
	  }
	))


	/////////// register user /////////
	passport.use('register-user', new LocalStrategy(
	  {
	    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
	    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
	    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
	  },
	  async function (username, password, done) {

	    //new_salt = await change_salt(global_salt, true)
	    key_result = await key_func(password, global_salt) // we use the salt as an array buffer to gen the pwd, but
	    string_salt = await change_salt(global_salt, false) // we store it as a string.

	    console.log(string_salt)
	    db.prepare('INSERT INTO USERS (username, password, salt) VALUES(?, ?, ?)').run(username,key_result.toString(),string_salt.toString())
	    
	    if (key_result === key_result) {
	      const user = { 
		username: username,
		password: key_result.toString(),
		description: 'the only user that deserves to get to this server'
	      }
	      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
	    }
	    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
	  }
	))


	app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)

	app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
	// We will store in the session the complete passport user object
	passport.serializeUser(function (user, done) {
		return done(null, user)
	})

	// The returned passport user is just the user object that is stored in the session
	passport.deserializeUser(function (user, done) {
		return done(null, user)
	})

	app.use(cookieParser())

	passport.use('jwtCookie', new JwtStrategy(
	  {
	    jwtFromRequest: (req) => {
	      if (req && req.cookies) { return req.cookies.jwt }
	      return null
	    },
	    secretOrKey: jwtSecret
	  },
	  function (jwtPayload, done) {
	    if (jwtPayload.sub) {
	      const user = { 
		username: jwtPayload.sub,
		description: 'one of the users that deserve to get to this server',
		role: jwtPayload.role ?? 'user'
	      }
	      return done(null, user)
	    }
	    return done(null, false)
	  }
	))


	//////optional OAUTH ////
	app.get('/oauth2cb', async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
	  /**
	   * 1. Retrieve the authorization code from the query parameters
	   */
	  const code = req.query.code // Here we have the received code
	  if (code === undefined) {
	    const err = new Error('no code provided')
	    err.status = 400 // Bad Request
	    throw err
	  }

	  /**
	   * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
	   */
	  const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
	    client_id: process.env.OAUTH2_CLIENT_ID,
	    client_secret: process.env.OAUTH2_CLIENT_SECRET,
	    code
	  })

	  console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.

	  // Let us parse them ang get the access token and the scope
	  const params = new URLSearchParams(tokenResponse.data)
	  const accessToken = params.get('access_token')
	  const scope = params.get('scope')

	  // if the scope does not include what we wanted, authorization fails
	  if (scope !== 'user:email') {
	    const err = new Error('user did not consent to release email')
	    err.status = 401 // Unauthorized
	    throw err
	  }

	  /**
	   * 3. Use the access token to retrieve the user email from the USER_API endpoint
	   */
	  const userDataResponse = await axios.get(process.env.USER_API, {
	    headers: {
	      Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
	    }
	  })
	  console.log(userDataResponse.data)

	  /**
	   * 4. Create our JWT using the github email as subject, and set the cookie.
	   */
	  await create_JWT(req, res, userDataResponse.data.login, oauth=true)
	})
	
	
	////// --------------------- OIDC
	// 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
	const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)

	// 2. Setup an OIDC client/relying party.
	const oidcClient = new oidcIssuer.Client({
	client_id: process.env.OIDC_CLIENT_ID,
	client_secret: process.env.OIDC_CLIENT_SECRET,
	redirect_uris: [process.env.OIDC_CALLBACK_URL],
	response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
	})
	
	// 3. Configure the strategy.
  	passport.use('oidc', new OpenIDConnectStrategy({
    		client: oidcClient,
    		usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  	}, (tokenSet, userInfo, done) => {
    	console.log(tokenSet, userInfo)
    	if (tokenSet === undefined || userInfo === undefined) {
      		return done('no tokenSet or userInfo')
    	}
    	return done(null, userInfo)
  	}))
  	
  	app.get('/oidc/login',
	  passport.authenticate('oidc', { scope: 'openid email' })
	)
	
	app.get('/oidc/cb', passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }), async (req, res) => {
	/**
	* Create our JWT using the req.user.email as subject, and set the cookie.
	*/
		await create_JWT(req, res, req.user.email, oauth=true) //The only difference is that now the sub claim will be set to req.user.email
	})
  	//// ------------------------------

	app.get('/',
	  passport.authenticate(
	    'jwtCookie',
	    { session: false, failureRedirect: '/login' }
	  ),
	  (req, res) => {
	    res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
	  }
	)

	app.get('/onlyexaminers ',
	  passport.authenticate(
	    'jwtCookie',
	    { session: false, failureRedirect: '/login' }
	  ),
	  (req, res) => {
	    if(req.user.examiner){
	      res.send('hello examiner') // we can get the username from the req.user object provided by the jwtCookie strategy
	    }
	    else{
	      res.redirect('/');
	    }
	  }
	)

	app.get('/login',
	  (req, res) => {
	    res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
	  }
	)

	app.get('/register',
	  (req, res) => {
	    res.sendFile('register.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /register
	  }
	)
	app.post('/register', 
	  passport.authenticate('register-user', { failureRedirect: '/register', session: false }), // we indicate that this endpoint must pass through our 'register-user' passport strategy, which we defined before
	  (req, res) => {
	    res.redirect('/')
	    
	    // And let us log a link to the jwt.io debugger for easy checking/verifying:
	    console.log(`New user registered: `)
	    console.log(`Userame: ${req.user.username}`)
	    console.log(`Password: ${req.user.password}`)
	  }
	)


	app.post('/login', 
	  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
	  async (req, res) => { 
	    await create_JWT(req, res) 
	    // This is what ends up in our JWT
	  }
	)

	app.get('/logout', function (req, res) {
	  res.clearCookie('jwt');
	  res.redirect('/');
	});

	app.use(function (err, req, res, next) {
	  console.error(err.stack)
	  res.status(500).send('Something broke!')
	})

	app.listen(port, () => {
	  console.log(`Example app listening at http://localhost:${port}`)
	})
}

main().catch(e => { console.log(e) })
