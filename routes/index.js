const express = require("express");
const routerV1 = require("./v1");

const router = express.Router();

router.get("/", (req, res) => {
    res.send("Work For We server is running!!!");
});

router.use("/api/v1", routerV1);

module.exports = router;
