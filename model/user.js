const mongoose = require("mongoose")
const bcrypt =  require("bcryptjs");
const jwt = require('jsonwebtoken')

const userSchema = new mongoose.Schema({
    name:{
        type: String,
        required: [true, "Please provide first name"],
        trim: true,
    },
    email: {
        type: String,
        required: [true, "Please provide email"],
        match: [
            /^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/,
            "Please provide valid email",
        ],
        trim: true,
        lowercase: true,
    },
    login_by:{
        type:String,
        enum:['Google','Normal']
    },
    password: {
        type: String,
        required: [true, "Please provide password"],
    },
    phoneNumber: {
        type: String,
        required: [false, "Please provide phone number"],
        unique:[true,'Phone Number is Already registerd'],
        trim: true,
    },
    isVerified: {
        type:Boolean,
        default:true
    },
});
userSchema.methods.generateJWT = function () {
    return jwt.sign({ userId: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRATION,
    });
};
userSchema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports =  mongoose.model("User", userSchema, "user");