const db = require('../config/db');

exports.getAdminDashboard = async (req, res) => {
    res.render('admin/dashboard', { message: null });
}

exports.getAddFood = (req, res) => {
    res.render('admin/addFood');
}

exports.postAddFood = async (req, res) => {
    try {
        const{name, description, image_url, price} = req.body;

        //validating data entry
        if (!name || !description || !image_url || !price) {
            return res.render('admin/addFood', { message: 'All fields are required.' });
        }
        // Inserting food item into the database
        await db.none('INSERT INTO food_items (name, description, image_url, price) VALUES ($1, $2, $3, $4)', 
            [name, description, image_url, price]);

        res.redirect('/admin/food');
    }catch (error) {
        console.error('Error adding food item:', error);
        res.status(500).send('Server error while adding food item.');
    }
}

// Get all food items for admin
exports.getAllFood = async (req, res) => {
    try{
        const foodItems = await db.any('SELECT * FROM food_items');
        res.render('admin/foodList', { foods: foodItems });
    }catch (error) {
        console.error('Error fetching food items:', error);
        res.status(500).send('Server error while fetching food items.');
    }
}

//get edit form 
exports.getEditFood = async (req, res) => {
    try{
        const food = await db.one('SELECT * FROM food_items WHERE id = $1', [req.params.id]);
        if (!food) {
            return res.status(404).send('Food item not found');
        }
        res.render('admin/editFood', { food }); 

    } catch (error) {
        console.error('Error fetching food item:', error);
        res.status(500).send('Server error while fetching food item.');
    
    }
}

// Post edit form
exports.postEditFood = async (req, res) => {
    const { id } = req.params;
    const { name, description, image_url, price } = req.body;
    try {
        await db.none('UPDATE food_items SET name = $1, description = $2, image_url = $3, price = $4 WHERE id = $5',
            [name, description, image_url, price, id]);

        res.redirect('/admin/food');
        } catch (error) {
            console.error('Error updating food item:', error);
            res.status(500).send('Server error while updating food item.');
        }
}


// Delete food item
exports.deleteFood = async (req, res) => {
    const { id } = req.params;
    try {
        await db.none('DELETE FROM food_items WHERE id = $1', [id]);
        res.redirect('/admin/food');
    } catch (error) {
        console.error('Error deleting food item:', error);
        res.status(500).send('Server error while deleting food item.');
    }
}