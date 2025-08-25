const express = require('express');
const {createCompanyAdmin} = require('../controllers/superAdminController');
const upload = require('../middleware/multer');
const { route } = require('./authRoutes');

const router = express.Router();

router.post('/add-company-admin',upload.single('logo'),createCompanyAdmin);

module.exports = router;