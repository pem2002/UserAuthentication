const express = require('express');
const router = express.Router();
const adminController = require('../controller/adminController');

// Admin dashboard
router.get('/dashboard', adminController.getAdminDashboard);

// Add food
router.get('/add-food', adminController.getAddFood);
router.post('/add-food', adminController.postAddFood);

// View all food items
router.get('/food', adminController.getAllFood);

// Edit food
router.get('/edit-food/:id', adminController.getEditFood);
router.post('/edit-food/:id', adminController.postEditFood); 

// Delete food
router.post('/delete-food/:id', adminController.deleteFood);

module.exports = router;
