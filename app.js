const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const { request } = require('http');

const connection = mysql.createConnection({
	host     : 'localhost',
	user     : 'root',
	password : '',
	database : 'nodelogin'
});

const app = express();

app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));

app.get('/', function(request, response) {
	response.sendFile(path.join(__dirname + '/login.html'));
});

//login dengan email dan username
app.post('/login', (request, response) => {
    const username = request.body.username;
    const password = request.body.password;

    if (username && password) {
        authenticateUser(username, password, (error, results) => {
            if (error) {
                response.status(500).json({ error: 'Internal Server Error' });
            } else {
                if (results.length > 0) {
                    request.session.loggedin = true;
                    request.session.username = username;
                    response.redirect('/home');
                } else {
                    response.status(401).json({ error: 'Incorrect Username and/or Password!' });
                }
            }
            response.end();
        });
    } else {
        response.status(400).json({ error: 'Please enter Username and Password!' });
        response.end();
    }
});

//mendapatkan username yang sedang login
app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		response.send('Welcome back, ' + request.session.username + '!');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});

app.post('/logout', (req, res) => {
	// Hapus informasi otentikasi dari session
	req.session.destroy((err) => {
	  if (err) {
		console.error(err);
		res.status(500).json({ error: 'Gagal melakukan logout' });
	  } else {
		res.json({ message: 'Logout berhasil' });
	  }
	});
  });

//registrasi
app.post('/register', (request, response) => {
    const username = request.body.username;
    const password = request.body.password;
    const email = request.body.email;
    if (username && password && email) {
        registerUser(username, password, email, (error, result) => {
            if (error) {
                response.status(500).json({ error: 'Internal Server Error' });
            } else {
                response.status(201).json({ message: 'Registration successful' });
            }
        });
    } else {
        response.status(400).json({ error: 'Please enter Username, Password, and Email!' });
        response.end();
    }
});

//delete user
app.delete('/delete', (request, response) => {
	const username = request.body.username;
	const password = request.body.password;
	const email = request.body.email;
	if ((email || username) && password) {
		deleteUser(username, password, email, (error, result) => {
			if (error) {
				response.status(500).json({error: 'Internal Server Error'})
			} else {
				response.status(201).json({message: 'Delete successful'})
			}
		});
	} else {
		response.status(400).json({error: 'Please enter correct Username/email and password'})
		response.end()
	}
})

//api setelah login
app.get('/api/protected', (req, res) => {
	if (req.session.user) {
	  res.json({ message: 'Halaman terproteksi' });
	} else {
	  res.status(401).json({ message: 'Akses ditolak. Silakan login terlebih dahulu.' });
	}
  });


function authenticateUser(username, password, callback) {
    connection.query('SELECT * FROM accounts WHERE username = ? AND password = ?', [username, password], callback);
}

function registerUser(username, password, email, callback) {
    connection.query('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)', [username, password, email], callback);
}

function deleteUser(username, password, email, callback) {
	let deleteQuery = 'DELETE FROM accounts WHERE password = ?';
	if (username) {
		deleteQuery += 'AND username = ?'
	} else if (email) {
		deleteQuery += 'AND email = ?'
	}
	connection.query(deleteQuery, [password, username || email], callback)
}

app.listen(3000);