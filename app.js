const mysql = require('mysql');
const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();
// const { request } = require('http');

//koneksi ke database
const connection = mysql.createConnection({
	host     : 'localhost',
	user     : 'root',
	password : '',
	database : 'nodelogin'
});

connection.connect((err) => {
	if (err) {
	  console.error('Koneksi database gagal:', err);
	  return;
	}
	console.log('Terhubung ke database');
  });



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
	const email = request.body.email;
    if ((username || email) && password) {
        authenticateUser(username, email, password, (error, results) => {
            if (error) {
                response.status(500).json({ error: 'Internal Server Error' });
            } else {
                if (results.length > 0) {
                    request.session.loggedin = true;
                    request.session.username = username;
                    request.session.email = email;
                    response.redirect('/home');
                    // response.redirect('/username/:email');
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

//mendapatkan pesan setelah login
app.get('/home', function(request, response) {
	if (request.session.loggedin) {
		response.send('Welcome back!!');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});

//api setelah login
app.get('/api/protected', (request, result) => {
	if (request.session.loggedin) {
	  result.json({ message: 'Halaman terproteksi' });
	} else {
	  result.status(401).json({ message: 'Akses ditolak. Silakan login terlebih dahulu.' });
	}
  });


// Endpoint untuk mendapatkan data berdasarkan username
app.get('/username/:email', (req, res) => {
	const requestedUsername = req.params.email;
	// Query SQL dengan WHERE clause untuk mendapatkan data berdasarkan username
	const query = 'SELECT * FROM accounts WHERE email = ?';
	connection.query(query, [requestedUsername], (err, results) => {
	  if (err) {
		console.error('Kesalahan query:', err);
		res.status(500).send('Terjadi kesalahan server');
	  } else {
		res.json({
			username: results[0].username,
		});
	  }
	});
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


  function authenticateUser(username, email, password, callback) {
    const connectionQuery = 'SELECT * FROM accounts WHERE (username = ? OR email = ?) AND password = ?';
    connection.query(connectionQuery, [username, email, password], callback);
}

function registerUser(username, password, email, callback) {
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            callback(err);
            return;
        }
        connection.query('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)', [username, hash, email], callback);
    });
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