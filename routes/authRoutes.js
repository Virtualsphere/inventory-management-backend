const express = require('express');
const { registerUser, loginUser, superAdmin, loginSuperAdmin, loginCompanyAdmin } = require('../controllers/authController');

const router = express.Router();

router.post('/register',registerUser);
router.post('/login',loginUser);
router.post('/add-superAdmin',superAdmin);
router.post('/login-superAdmin',loginSuperAdmin);
router.post('/login-companyAdmin',loginCompanyAdmin);

module.exports = router;