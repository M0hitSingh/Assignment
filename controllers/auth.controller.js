const asyncWrapper = require("../util/asyncWrapper");
const User = require("../model/user")
const otp = require('../model/otp')
const {createCustomError} = require('../errors/customAPIError')
const otpGenrator = require('otp-generator')
const mail = require("../util/email");
const bcrypt = require('bcrypt');
const { sendSuccessApiResponse } = require("../middleware/successApiResponse");

const signup = asyncWrapper(async (req,res,next)=>{
    try{
        const { name,phone,email, password } = req.body;
        console.log(req.body)
        const emailisActive = await User.findOne({ email, isActive: true , isVerified:true});
        if (emailisActive) {
            const message = "Email is already registered";
            return next(createCustomError(message, 406));
        }
        const OTPgen = otpGenrator.generate(5,{
            digits:true, lowerCaseAlphabets : false, upperCaseAlphabets:false,
            specialChars:false
        })
        const OTP = await otp.updateOne({email:email},{email:email , otp:OTPgen},{upsert:true});
        mail.sendEmail(email,OTPgen)
        console.log("sending otp")
        const salt = await bcrypt.genSalt(10);
        const hashpass = await bcrypt.hash(password,salt);
        const user = await User.create({
            name:name,
            phoneNumber:phone,
            email:email,
            password:hashpass
        });
        const data = {user,token: user.generateJWT()} 
        res.json(sendSuccessApiResponse(data,201));
    }
    catch(err){
        console.log(err)
        return createCustomError(err,400);
    }
})

const login = asyncWrapper(async (req,res,next)=>{
    try{
        const { email, password } = req.body;
        
        console.log(req.body)
        const emailExists = await User.findOne(
            { email},
        );
        if (!emailExists) {
            const message = "Invalid credential";
            return next(createCustomError(message, 401));
        }   
        console.log(emailExists)
    
        const isPasswordRight = await emailExists.comparePassword(password);
        if (!isPasswordRight) {
            const message = "Invalid credentials";
            return next(createCustomError(message, 401));
        }
    
        const data = {
            name: emailExists.name,
            email: emailExists.email,
            token: emailExists.generateJWT(),
        };
        const tkn  = data.email;
        console.log(data);
        res.render('addorder',{tkn})
        // res.status(200).json(sendSuccessApiResponse(data));
    }
    catch(err){
        return createCustomError(err,400);
    }
})


module.exports = {
    login,
    signup
}