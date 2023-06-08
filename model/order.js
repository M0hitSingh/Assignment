const mongoose = require("mongoose")
const schema = mongoose.Schema;

const orderSchema = new mongoose.Schema(
    {
        user_id:{
            type:schema.Types.ObjectId,
            ref:'User',
        },
        sub_total:{
            type:String,
            require:[true,'Please Enter Sub Total for your Order']
        },
        phoneNumber:{
            type:String,
            require:[true,'Plese Provide Phone number']
        }
    }
);

module.exports = mongoose.model("order", orderSchema, "order");
