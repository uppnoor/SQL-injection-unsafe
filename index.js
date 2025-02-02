const express = require('express');
const app = express();
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.json());

app.set('view engine', 'ejs');

function sessionValidation(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

const expireTime = 24 * 60 * 60 * 1000; 
const session_secret = process.env.NODE_SESSION_SECRET;
const mongo_password = process.env.MONGO_PASSWORD;
const mongo_user = process.env.MONGO_USER;
const mongo_session_secret = process.env.SESSION_SECRET;
const mysql_password = process.env.MYSQL_DB_PASSWORD;
const mysql_username = process.env.MYSQL_USERNAME;

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongo_user}:${mongo_password}@cluster0.fwhcn.mongodb.net/assignment1?retryWrites=true&w=majority`,
    collectionName: 'cookies'
});

const db = mysql.createConnection({
    host: 'mysql-194ec402-uppnoor41-36de.f.aivencloud.com',
    port: my_sql_port,
    user: mysql_username,
    password: mysql_password,
    database: 'defaultdb',
    ssl: {
      rejectUnauthorized: true,
      ca: process.env.MYSQL_CA_CERT,
    },
  });

db.connect(err => {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        return;
    }
    console.log('Connected to MySQL database.');
});

app.use(session({ 
    secret: session_secret,
    store: mongoStore,
    saveUninitialized: false, 
    resave: true,
    cookie: {
        maxAge: expireTime,
        httpOnly: true
    }
}));

app.get('/', (req, res) => {
    if(req.session.authenticated) {
        const username = req.session.username;
        res.render('loggedIn', { username });
    } else {
        res.render('index');
    }
});

app.get('/signup', (req, res) => {
    var error = req.query.error;
    res.render('signup', { error });
});

app.get('/login', (req, res) => {
    var error = req.query.error;
    res.render('login', { error });
});

app.get('/members', sessionValidation, (req, res) => {
    const username = req.session.username;
    const randomValue = Math.floor(Math.random() * 3) + 1;
    res.render('members', { username, randomValue });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Session destruction error:", err);
        }
        res.redirect("/");
    });
});

// ----- INSECURE SIGNUP: The query uses string concatenation -----
app.post('/signup-submit', async (req, res) => {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    if (!username || !email || !password) {
        return res.redirect('/signup?error=Please fill in all fields');
    }

    // Insecure query (vulnerable to injection if the user can manipulate 'email')
    const checkEmailQuery = "SELECT email FROM users WHERE email = '" + email + "'";

    db.query(checkEmailQuery, async (err, result) => {
        if (err) {
            console.error("Error querying email:", err);
            return res.status(500).send('Server error');
        }

        if (result.length > 0) {
            return res.redirect('/signup?error=Email already registered');
        }

        // insecure query using string concatenation
        const insertUserQuery = 
            "INSERT INTO users (username, email, password) VALUES ('" + username + "', '" + email + "', '" + hashedPassword + "')";

        db.query(insertUserQuery, (err, result) => {
            if (err) {
                console.error('Error inserting user:', err);
                return res.status(500).send('Error signing up');
            }
            res.redirect('/login');
        });
    });
});

// ----- INSECURE LOGIN: The query uses string concatenation -----
app.post('/login-submit', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.redirect('/login?error=Please fill in all fields');
    }

    // Insecure query (vulnerable to injection if the user can manipulate 'email')
    const loginUserQuery = "SELECT * FROM users WHERE email = '" + email + "'";

    db.query(loginUserQuery, async (err, results) => {
        if (err) {
            console.error('Error checking user:', err);
            return res.status(500).send('Error logging in');
        }

        if (results.length === 0) {
            return res.redirect('/login?error=Invalid email or password');
        }

        const user = results[0];

        try {
            const isValid = await bcrypt.compare(password, user.password);

            if (isValid) {
                req.session.authenticated = true;
                req.session.username = user.username;
                req.session.cookie.maxAge = expireTime;
                return res.redirect(`/`);
            } else {
                return res.redirect('/login?error=Invalid email or password');
            }
        } catch (bcryptError) {
            console.error('Error comparing passwords:', bcryptError);
            return res.status(500).send('Server error');
        }
    });
});

app.get('*', (req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
