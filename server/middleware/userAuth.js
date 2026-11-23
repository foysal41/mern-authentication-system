// This code base will find the token from the cookie & From that token if will find the user id 

import jwt from "jsonwebtoken";


const userAuth = async (req, res, next) => {
    const {token}  = req.cookies;

    if(!token) {
        return res.json({success: false, message: "Not Authorized login. Please try again."})
    }


    // If token we found
    try{
        //1) Decode the token
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET)

        //2) find ID from JWT Decode
        if(tokenDecode.id) {
            if (!req.body) req.body = {};
            req.body.userId = tokenDecode.id;
        }else{
            res.json({success: false, message:"Not Authorized. Login in again"})
        }


        next();
    }catch(error) {
        res.json({success: false, message:error.message})
    }
}


export default userAuth;