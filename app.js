const express = require('express')
const helpers = require('./_helpers');
const db = require('./models')
const User = db.User
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}

const passport = require('./config/passport')

const app = express()
const port = 3000

// use helpers.getUser(req) to replace req.user
function authenticated(req, res, next) {
  passport.authenticate('jwt', { session: false })
  next()
};
app.post('/api/signin', (req, res) => {
  // 檢查必要資料
  if (!req.body.email || !req.body.password) {
    return res.json({ status: 'error', message: "required fields didn't exist" })
  }
  // 檢查 user 是否存在與密碼是否正確
  let username = req.body.email
  let password = req.body.password

  User.findOne({ where: { email: username } }).then(user => {
    if (!user) return res.status(401).json({ status: 'error', message: 'no such user found' })
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ status: 'error', message: 'passwords did not match' })
    }
    // 簽發 token
    var payload = { id: user.id }
    var token = jwt.sign(payload, process.env.JWT_SECRET)
    return res.json({
      status: 'success',
      message: 'ok',
      token: token,
      user: {
        id: user.id, name: user.name, email: user.email, role: user.role
      }
    })
  })
})

app.get('/', (req, res) => res.send('Hello World!'))
app.listen(port, () => console.log(`Example app listening on port ${port}!`))

module.exports = app
