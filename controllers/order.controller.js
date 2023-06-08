const asyncWrapper = require("../util/asyncWrapper");
const { createCustomError } = require('../errors/customAPIError')
const { sendSuccessApiResponse } = require("../middleware/successApiResponse");
const User = require('../model/user');
const Order = require('../model/order');

const addOrder = asyncWrapper(async (req,res,next)=>{
    const sub_total = req.body.sub_total;
    const phoneNumber = req.body.phoneNumber;
    const isUser = await User.find();
    if (!isUser) {
        const message = "User Not Exist";
        return next(createCustomError(message, 401));
    }
    await Order.create({
        user_id:isUser._id,
        sub_total:sub_total,
        phoneNumber:phoneNumber
    })
    const response = sendSuccessApiResponse('Order Added Succesfully',201);
    // req.json(response); 
    res.render('addorder');
})

const viewOrder = asyncWrapper(async (req,res,next)=>{
    const userId = req.user.userId;
    const isUser = await User.findById();
    if (!isUser) {
        const message = "User Not Exist";
        return next(createCustomError(message, 401));
    }
    const myOrders = await Order.find({user_id:userId})
    console.log(myOrders);
    const response = sendSuccessApiResponse(myOrders,203);
    res.render('view-order',{myOrders})
    // req.status(201).json(response); 
})

module.exports = {
    addOrder,
    viewOrder
}