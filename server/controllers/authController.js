import bcrypt from "bcryptjs";
import userModel from "../models/userModel.js";
import jwt from "jsonwebtoken";

// For user registration
 const register  = async (req, res) => {
    const {name, email, password} = req.body;

    if(!name || !email || !password){
        return res.status(201).json({
            success: false,
            message: "Missing Details"
        })
    }


    try{
        //1)  if any user "EMAIL" available find that email from db checking
        // if "EMAIL"  not exist then we'll give permission to create the account. 
        const existingUser = await userModel.findOne({email})
        if(existingUser){
            return res.json({success: false, message: "User already exists"});
        }


        const hashedPassword = await bcrypt.hash(password, 10);


        //2) Now we're creating the user 
        const user = new userModel({name, email, password: hashedPassword})

        //3) Now save the user data into db
        await user.save();


        // 4) Generate token 
        const token = jwt.sign({id: user._id} , process.env.JWT_SECRET, {expiresIn: '7d'})


        // 5) send this TOKEN to Cookies
        res.cookie('token' , token , {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'node' : 'strict',
            maxAge: 7 * 24 * 60 * 1000 

        })

        return res.json({success: true})

    }catch(error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

// For User Login
 const login = async (req, res) => {
    const {email, password} = req.body

    //1) Check email and password
    if(!email || !password) {
        return res.json({success: false, message: "Email and password are required"})
    }

    try{
    const user = await userModel.findOne({email});
    if(!user) {
        return res.json({success: false, message: "Invalid email"})
    }

    const isMatch = await bcrypt.compare(password, user.password)
    if(!isMatch){
        return res.json({success: false, message: "Invalid password"})
    }


    //2) Again generate the token for login  
        const token = jwt.sign({id: user._id} , process.env.JWT_SECRET, {expiresIn: '7d'})


        //3) send this TOKEN to Cookies
        res.cookie('token' , token , {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'node' : 'strict',
            maxAge: 7 * 24 * 60 * 1000 

        });

        return res.json({success: true})

    }catch(error) {
        return res.json({success: false, message:error.message})
    }
}


// For user logout

 const logout = async(req, res)  => {
    try{
         res.clearCookie('token' , {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',           
        });

        return res.json({success: true, message: "Logged Out"})
    }catch(error) {
     res.json({success: false, message:error.message})
    }
}


export const authController ={
    register,
    login, 
    logout
}