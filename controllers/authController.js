const pool = require("../db/db");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');


exports.superAdmin = async(req,res) =>{
    const { email,password } = req.body;
    let connection;
    try {
        if(!email || !password){
            return res.status(404).json({
                message:"Email and password is required to create super admin account"
            })
        }
        
        connection = await pool.getConnection(); 
        const [user] = await connection.query(
            "SELECT * FROM users WHERE email = ? AND role_id = ?",
            [email,6]
        )
       if(user.length !=0){
            return res.status(409).json({
                message:'User already exists! Please Login'
            })
        }
        //hash the password
        const hashedPassword = await bcrypt.hash(password,10);
        await connection.query(
            "INSERT INTO users (email,password,role_id) VALUES(?,?,?)",
            [email,hashedPassword,6]
        )
        return res.status(201).json({
            message: 'Super Admin account created successfully'
        });
    } catch (error) {
        console.log('failed to register the new user');
        return res.status(500).json(error.message);
    }finally{
        if (connection) connection.release();
    }
}

exports.loginSuperAdmin = async (req, res) => {
  let connection;
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and Password are required to login the user",
      });
    }

    connection = await pool.getConnection();

    const [row] = await connection.query(
      "SELECT id, email, password, role_id FROM users WHERE email = ? AND role_id = ?",
      [email, 6]
    );

    if (row.length === 0) {
      return res.status(404).json({
        message: "Super admin doesn't exist with this email",
      });
    }

    const user = row[0];

    // match the password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({
        message: "Password is incorrect",
      });
    }

    // generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role_id: user.role_id },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.status(200).json({
      message: "Super Admin login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        role_id: user.role_id,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json(error.message);
  } finally {
    if (connection) connection.release();
  }
};

exports.loginCompanyAdmin = async(req,res) =>{
    let connection
    const { companyName,password } = req.body;
    try {
        if(!companyName || !password){
            return res.status(404).json({
                message:"Company Name and password is requried"
            })
        }
        connection = await pool.getConnection();

        const [row] = await connection.query(
            "SELECT id,company,password FROM users WHERE company = ? AND role_id = ?",
            [companyName,7]
        )
        if(row.length === 0){
            return res.status(409).json({
                message:"Account doesn't exists"
            })
        }
        const user = row[0];

        //match the password
        const isPasswordCorrect = await bcrypt.compare(password,user.password);
        if(!isPasswordCorrect){
            return res.status(404).json({
                message:"Password is incorrect"
            })
        }
        // generate JWT
        const token = jwt.sign(
        { id: user.id, company: user.company, role_id: user.role_id },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
        );

        return res.status(202).json({
            message:"Company Admin logged in successfully",
            token,
            user:{
                userId:user.id,
                companyName:user.company
            }
        })
    } catch (error) {
        console.log(error);
        return res.status(500).json(error.message);
    }
}

exports.registerUser = async(req,res) =>{
    const { firstName,lastName,userName,email,password,role } = req.body;

    let connection
    try {
        if(!firstName){
            return res.status(400).json({
                message:'Please enter the first name'
            })
        }if(!lastName){
            return res.status(400).json({
                message:'Please enter the last name'
            })
        }if(!userName){
            return res.status(400).json({
                message:'Please enter user name'
            })
        }if(!email){
            return res.status(400).json({
                message:'Please enter your email'
            })
        }if(!password){
            return res.status(400).json({
                message:'Please enter your password'
            })
        }if(!role){
            return res.status(400).json({
                message:'Please enter your role'
            })
        }

        connection = await pool.getConnection()
        //check is the user exists or not
        const [user] = await connection.query(
            "SELECT email FROM users WHERE email = ?",
            [email]
        )
        if(user.length !=0){
            return res.status(409).json({
                message:'User already exists! Please Login'
            })
        }
        //hash the password
        const hashedPassword = await bcrypt.hash(password,10);

        //store in the database
        await connection.query(
            "INSERT INTO users (firstName,lastName,userName,email,password,role_id) VALUES(?,?,?,?,?,?)",
            [firstName,lastName,userName,email,hashedPassword,role]
        )
        return res.status(201).json({
            message: 'User registered successfully'
        });
    } catch (error) {
        console.log('failed to register the new user');
        return res.status(500).json(error.message);
    }finally{
        if (connection) connection.release();
    }
}

exports.loginUser = async(req,res) =>{
    const { email,password,role_id } = req.body;
    console.log("Body;",req.body);
    let connection

    try {
        if(!email){
            return res.status(400   ).json({message:'Email is required'})
        }
        if(!password){
            return res.status(400   ).json({message:'Password is required'});
        }
        if(!role_id){
            return res.status(400   ).json({message:'Role Id is required'});
        }
        
        connection = await pool.getConnection()
        
        //check if user already exists or not
        const [user] = await connection.query(
            "SELECT * FROM users WHERE email = ? AND role_id = ?",
            [email,role_id]
        )
        console.log("User:",user);
        if (user.length === 0) {
          return res
            .status(401)
            .json({ message: "Invalid email, password or role" });
        }
        const userData = user[0]

        //verify password
        const isPasswordValid = await bcrypt.compare(password,userData.password);
        if (!isPasswordValid) {
          return res
            .status(401)
            .json({ message: "Invalid email/mobile or password" });
        }

        //create jwt token
        const token = jwt.sign(
            {
                id:userData.id,
                email:userData.email,
                role_id:userData.role_id
            },
            process.env.JWT_SECRET,
            { expiresIn:'24h' }
        )
        res.status(200).json({
            message:'User logged in successfully',
            token,
            user:{
                id:userData.id,
                email:userData.email,
                role_id:userData.role_id
            }
        })
    } catch (error) {
        console.log('failed to login the user',error.message);
        return res.status(500).json(error.message);
    }finally{
        if(connection){
            connection.release();
        }
    }
}

