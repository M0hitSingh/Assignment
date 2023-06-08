const express = require("express");
const router = express.Router();
const authRoutes = require('../controllers/auth.controller');
const orderRoutes = require("../controllers/order.controller");
const { authorization } = require("../middleware/authorization");


// auth
router.use('/auth/login',authRoutes.login)
router.use('/auth/signup',authRoutes.signup)

//order
router.post('/add-order',orderRoutes.addOrder)
router.get('/view/order',orderRoutes.viewOrder);


router.get("/", (req, res) => {
    res.send("Server is running!!!");
});

module.exports = router;
