const Pool = require('pg').Pool

const pool = new Pool({
    user: "postgres",
    password: "Nationalgeo123!",
    host: "localhost",
    port: 5433,
    database: "userauth"
})

module.exports = pool