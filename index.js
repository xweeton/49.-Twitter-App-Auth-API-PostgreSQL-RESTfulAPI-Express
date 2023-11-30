let express = require('express');
let path = require('path');
const cors = require('cors');
const { Pool } = require('pg');
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

let app = express()
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    require: true,
  },
});

async function getPostgresVersion() {
  const client = await pool.connect();
  try {
    const response = await client.query('SELECT version()');
    console.log(response.rows[0]);
  } finally {
    client.release();
  }
}

getPostgresVersion();


// signup endpoint
app.post('/signup', async (req, res) => {
  const client = await pool.connect();
  try {
    // hash the password
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);

    // check for existing username
    const userResult = await client.query('SELECT * FROM users WHERE username = $1', [username]);

    // if username already exists, return response
    if (userResult.rows.length > 0) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // if user doesn't exist, then proceed it
    await client.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);

    res.status(201).json({ message: "User registered successfully" });

  } catch (error) {
    console.error('Error: ', error.message)
    res.status(500).json({ error: error.message })

  } finally {
    client.release();
  }
});


// login endpoint
app.post('/login', async (req, res) => {
  const client = await pool.connect();

  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [req.body.username]);

    // if user found, store it in 'user' variable
    const user = result.rows[0];

    // if user not found, return an error response
    if (!user) return res.status(400).json({ message: "Invalid username or password" });

    //verify if request body password is same as user actual password
    const passwordIsValid = await bcrypt.compare(req.body.password, user.password);
    // if not valid, return error and set token null
    if (!passwordIsValid) return res.status(401).json({ auth: false, token: null });

    // else, pass in 3 arguement tp jwt.sign() methhod to generate a JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: 86400 });
    // return token back to user(frontend)
    res.status(200).json({ auth: true, token: token });

  } catch (error) {
    console.error('Error: ', error.message);
    res.status(500).json({ error: error.message });

  } finally {
    client.release();
  }

});


app.get('/username', (req, res) => {
  // check if the authorization bearer token was provided
  const authToken = req.headers.authorization;

  if (!authToken) return res.status(401).json({ error: 'Access Denied' });

  try {
    //verify the token
    const verified = jwt.verify(authToken, SECRET_KEY);
    // fetching the username from token
    res.json({
      username: verified.username
    });

  } catch (err) {
    // return error if token not valid
    res.status(400).json({ error: 'Invalid Token' });

  }
});


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname + '/index.html'));
})

app.listen(3000, () => {
  console.log('App is listening on port 3000');
})