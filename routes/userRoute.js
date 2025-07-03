 const express = require('express');
const router = express.Router();
const userController = require('../controller/userController');

router.get('/dashboard', userController.getDashboard);
router.get('/food', userController.getAllFood);

module.exports = router;
