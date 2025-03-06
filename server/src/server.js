//modules
require('dotenv').config()
const { verify } = require('jsonwebtoken')
const express = require('express')
const cookieParser = require('cookie-parser') //access to req.cookies
const cors = require('cors')
const { hash, compare, genSalt } = require('bcrypt')
const pool = require('./database')
const  { createAccessToken, createRefreshToken } = require('./tokens')
const verifyAccessToken = require('./isAuth')

const app = express()

//middleware
app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true })) // supports URL-encoded bodies
app.use(cors())

// 1. Register a user

app.post('/user/register', async (req, res) => {
    const { email, password } = req.body

    // 1. check if user email already exists in database
    const foundUser = await pool.query(
        'SELECT * FROM "user" WHERE email = $1',
        [email]
    )

    if (foundUser.rows.length > 0) return res.status(409).json({success: false, message: "The email you're trying to register is already in use."})
    
    // 2. if not, hash their password & insert user into DB
    try {
        const salt = await genSalt()
        const hashedPassword = await hash(password, salt)
        await pool.query(
            'INSERT INTO "user" (email, password_hash) VALUES ($1, $2)',
            [email, hashedPassword]
        )
        res.status(201).send()
    } catch (error) {
        console.error(error.message)
        res.status(500).send()
    }
})

// 2. Login a user, POST because you're generating a web token

app.post('/user/login', async (req, res) => {
    const { email, password } = req.body

    try {
        // 1. Find user in DB
        const foundUser = await pool.query(
            'SELECT * FROM "user" WHERE email = $1',
            [email]
        )
        if (foundUser.rows.length === 0) return res.status(404).json({success: false, message: "This email has not yet been registered"})

        // 2. If found user, compare hashed password to password to check for correctness
        const response = await pool.query(
            'SELECT id, password_hash FROM "user" WHERE email = $1',
            [email]
        )
        const userID = response.rows[0].id
        const hashedPassword = response.rows[0].password_hash
        const valid = await compare(password, hashedPassword)
        if (!valid) return res.status(404).json({success: false, message: "Password does not match"})

        // 3. If passwords match, create refresh & access token, push refresh token to DB
        const accessToken = createAccessToken(userID)
        const refreshToken = createRefreshToken(userID)
        await pool.query(
            'UPDATE "user" SET refresh_token = $1 WHERE id = $2',
            [refreshToken, userID]
        )

        // 4. send refresh token as cookie, and access token as regular response
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            path: '/refresh_token'
        })
        res.status(201).json({success: true, accessToken: accessToken, userEmail: email})

    } catch (error) {
        console.error(error.message)
        res.status(500).send()
    }
})

// 3. Logout a user

app.post('/user/logout', async (req, res) => {
    const { email } = req.body

    // 1. Clear session cookie
    res.clearCookie('refreshToken', {path: '/refresh_token'})
    
    // 2. Removing refresh_token from DB
    try {
        const response = await pool.query(
            'SELECT id FROM "user" WHERE email = $1',
            [email]
        )
        const id = response.rows[0].id

        await pool.query(
            'UPDATE "user" SET refresh_token = NULL WHERE id = $1',
            [id]
        )
    
        res.status(200).json({success: true, accessToken: ""})
    } catch (error) {
        console.error(error.message)
        res.status(500).send()   
    }
})

// 4. Set up a protected route

app.post('/user/protected', async (req, res) => {
    try {
        // 1. Authenticate access token
        const userID = verifyAccessToken(req, res)

        // 2. If authenticated, user is granted access
        if (userID !== null) {
            return res.status(200).json({success: true, message: "You have access to protected route"})
        } 
    } catch (error) {
        console.error(error.message)
        res.status(500).send()   
    }
})


// 5. Get new access token with refresh
app.post('/refresh_token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken

    // 1. Check for refresh token 
    if (!refreshToken) return res.status(404).json({success: false, message: "No refresh token available"})

    // 2. If refresh token is present, verify() it
    let payload = null
    try {
        payload = verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
    } catch (error) {
        console.error(error.message)
        res.status(500).send()  
    }

    // 3. Refresh token is valid, check if user exists
    const userExists = await pool.query(
        'SELECT * FROM "user" WHERE id = $1',
        [payload.userID]
    )

    if (userExists.rows.length === 0) return res.status(404).json({success: false, message: "Refresh token is valid, but user does not exist"})

    // 4. User exists, check if refresh token belongs to user
    const user_Refresh_Token_Matches_Cookies_Refresh_Token = await pool.query(
        'SELECT * FROM "user" WHERE id = $1 AND refresh_token = $2',
        [payload.userID, refreshToken]
    )

    if (user_Refresh_Token_Matches_Cookies_Refresh_Token.rows.length === 0) return res.status(404).json({success: false, message: "Refresh tokens do not match"})

    // 5. Refresh tokens are all validated, create new refresh & access tokens
    const new_Access_Token = createAccessToken(payload.userID)
    const new_Refresh_Token = createRefreshToken(payload.userID)

    // 6. Update user's refresh token in DB
    await pool.query(
        'UPDATE "user" SET refresh_token = $1 WHERE id = $2',
        [new_Refresh_Token, payload.userID]
    )

    // 7. Send new refresh and access token to client
    res.cookie('refreshToken', new_Refresh_Token, {
        httpOnly: true,
        path: '/refresh_token'
    })

    res.status(201).json({success: true, accessToken: new_Access_Token})
})


app.listen(3058, () => console.log("Server is listening on port 3058..."))
