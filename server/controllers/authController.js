import bcrypt from "bcryptjs";
import userModel from "../models/userModel.js";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";

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

        //sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to Foysal Jaman",
            text: `Welcome to FJ website. Your Account has been created with email id: ${email}`

        }

        await transporter.sendMail(mailOptions)



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


// Send verification OTP to the user's email. 
const sendVerifyOtp = async(req, res) => {
    try{
        const {userId} = req.body;
        const user = await userModel.findById(userId);

        //1) Checking is email already verified or not
        if(user.isActiveVerified === true){
            return res.json({success: false, message: "Account Already Verified"})
        }

        //2) if email already not verified send OTP Number
        const otp = String(Math.floor(100000 + Math.random() * 900000))


        //3) Save this OTP in DB
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 *60 * 60 * 1000
        await user.save();

        //4) We are send "OTP" to user
         const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            text: `Your OTP is  ${otp}. Please Verify your account.`

        }
        await transporter.sendMail(mailOptions)
        res.json({success: true, message:'Verification OTP send on Email'})


    }catch(error) {
        res.json({success: false, message:error.message})
    }
}


// Suppose user has received the OTP on in the web & Verified the email
const verifyEmail = async (req, res) => {
     const {userId, otp} = req.body;
        if(!userId || !otp) {
            return res.json({success: false, Message: "Missing Details"})
        }


        try{
            //1) find the user from userId           
            const user = await userModel.findById(userId);

            //2) If user not found 
            if(!user) {
                 return res.json({success: false, Message: "User not found"})
            }

            //3) if OTP and VerifyOTP not Matched
            if(user.verifyOtp === '' || user.verifyOtp !== otp){
                 return res.json({success: false, Message: "Invalid OTP"})
            }


            //4) Check expire or not
            if(user.verifyOtpExpireAt < Date.now()){
                return res.json({success: false, Message: "OTP Expired"})
            }


            //5) If OTP is not expired THEN we'll verify the account
            user.isAccountVerified = true;

            user.verifyOtp = '';
            user.verifyOtpExpireAt =0;
            await user.save();
            return res.json({success: true, message: "Email Verified successfully"})


        }catch(error) {
             res.json({success: false, message:error.message})
        }
}


//Check if user is authenticated
const isAuthenticated = async (req, res) => {

    try{

        return res.json({success: true})
    }catch(error){
        res.json({success: false, message:error.message})
    }  
}

// Send password reset OTP
const sendResetOtp = async(req, res) => {
    const {email} = req.body;

    //1) if user email not provide for reset password
    if(!email) {
        return res.json({success: false, message:"Email is required"})
    }


    try{
        //2)  Server will find the email from DB
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: "User not found"})
        }

        
        //3) if email already not verified send OTP Number
        const otp = String(Math.floor(100000 + Math.random() * 900000))


        //4) Save this OTP in DB
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000 // 15 min
        await user.save();

        //5) We are send "OTP" to user
         const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            text: `Your OTP for resetting your password is   ${otp}. Use this OTP to proceed with resetting your password.`

        }
        await transporter.sendMail(mailOptions)
        return res.json({success: true, message:'OTP send to your email'})

    }catch(error) {
       res.json({success: false, message:error.message}) 
    }

}


// Reset User Password
const resetPassword = async(req, res) => {
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: "Email OTP, and New password are required"})
    }

    try{
        //1) find the user from DB
        const user = await userModel.findOne({email});
        if(!user){
             return res.json({success: false, message: "User not found"})
        }

        //2) if user OTP and DB OTP not Matched
        if(user.resetOtp === "" || user.resetOtp !== otp){
            return res.json({success: false, message: "Invalid OTP"})
        }

        //3) we'll check for expire 
        if(user.resetOtpExpireAt < Date.now()){
            return res.json({success: false, message: "OTP Expired"})
        }

        //4) If user is not expired then we'll save new password
        const hashedPassword = await bcrypt.hash(newPassword, 10)

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();
        return res.json({success: true, message: "Password has been reset successfully"})





    }catch(error){
        res.json({success: false, message:error.message})
    }
}


export const authController ={
    register,
    login, 
    logout,
    sendVerifyOtp,
    verifyEmail,
    isAuthenticated,
    sendResetOtp, 
    resetPassword,
    
}