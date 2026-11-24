

import express from 'express'
import { authController } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';
const authRouter = express.Router();


authRouter.post('/register' , authController.register)
authRouter.post('/login' , authController.login)
authRouter.post('/logout' , authController.logout)
authRouter.post('/send-verify-otp' , userAuth, authController.sendVerifyOtp)
authRouter.post('/verify-account' , userAuth, authController.verifyEmail)
authRouter.post('/is-auth' , userAuth, authController.isAuthenticated)
authRouter.post('/send-reset-otp' , authController.sendResetOtp);
authRouter.post('/reset-password' , authController.resetPassword)

export default authRouter;
