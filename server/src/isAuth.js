const { verify } = require('jsonwebtoken')

const verifyAccessToken = (req, res) => {
    const authorization = req.headers['authorization'] //'Bearer [access token]'
    if (!authorization) return res.status(400).json({success: false, message: "You need to login to access this page"})

    const token = authorization.split(" ")[1]

    const { userID } = verify(token, process.env.ACCESS_TOKEN_SECRET) //returns whatever we signed ACCESS_TOKEN_SECRET with in createAccessToken()
    return userID
}

module.exports = verifyAccessToken