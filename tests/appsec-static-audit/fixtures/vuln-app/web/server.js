const express = require('express');
const { exec } = require('child_process');
const app = express();
app.use(require('cors')());
app.get('/user/:id', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, r) => res.send(err.stack));
});
app.post('/exec', (req, res) => { exec('ls ' + req.body.dir); });
app.get('/page', (req, res) => { document.getElementById('x').innerHTML = req.query.q; });
localStorage.setItem('token', 'abc');
const saml = { wantAssertionsSigned: false };
res.cookie('sid', id, { httpOnly: false, secure: false });
