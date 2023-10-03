import express  from "express";
import mysql from 'mysql';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from "multer";
import path from "path";

const app = express();
app.use(cors(
    {
        origin: ["http://localhost:3000"],
        methods: ["POST", "GET", "PUT", "DELETE"],
        credentials: true
    }
));
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

const con = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"",
    database:"signup"
})

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images')
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
})

const upload = multer({
    storage: storage
})

con.connect(function(err) {
    if(err) {
        console.log("Error in Connection");
    } else {
        console.log("Connected");
    }
})

app.post('/login', (req, res) => {
    const sql = "SELECT * FROM users WHERE email = ? AND password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if(err) return res.json({Status: "Error", Error: "Error in running query"});
        if(result.length > 0) {
            const id = result[0].id;
            const token = jwt.sign({role: "admin"}, "jwt-secret-key", {expiresIn: '10d'});
            res.cookie('token', token);
            return res.json({Status: "Success"})
        } else {
            return res.json({Status: "Error", Error: "Wrong Email or Password"});
        }
    })
})

app.post('/residentlogin', (req, res) => {
    const sql = "SELECT * FROM resident WHERE email = ? AND password = ? ";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if(err) return res.json({Status: "Error", Error: "Error in running query"});
        if(result.length > 0) {           
            if(err) return res.json({Error: "password error"});                
            const token = jwt.sign({role: "resident", id: result[0].id}, "jwt-secret-key", {expiresIn: '10d'});
            res.cookie('token', token);
            return res.json({Status: "Success", id: result[0].id})                  
        } else {
            return res.json({Status: "Error", Error: "Wrong Email or Password"});
        }
    })
})

// app.get('/resident/:id', (req, res) => {
//     const id = req.params.id;
//     const sql = "SELECT * FROM resident where id = ?";
//     con.query(sql, [id], (err, result) => {
//         if(err) return res.json({Error: "Get resident error in sql"});
//         return res.json({Status: "Success", Result: result})
//     })
// })

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({Status: "Success"});
})

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if(!token) {
        return res.json({Error: " You are not Authorized"});
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if(err) return res.json({Error: "Token wrong"});
            req.role = decoded.role;
            req.id = decoded.id;
            next();
        })
    }
}

app.get('/dashboard',verifyUser, (req, res) => {
    return res.json({Status: "Success", role: req.role, id: req.id})
})

app.get('/adminCount', (req, res) => {
    const sql = "Select count(id) as admin from users";
    con.query(sql, (err, result) => {
        if(err) return res.json({Error: "Error in running query"});
        return res.json(result);
    })
})

app.get('/residentCount', (req, res) => {
    const sql = "Select count(id) as resident from resident";
    con.query(sql, (err, result) => {
        if(err) return res.json({Error: "Error in running query"});
        return res.json(result);
    })
})



app.post('/create',upload.single('image'), (req, res) => {
    const sql = "INSERT INTO resident (`name`,`phoneNo`,`email`,`password`,`address`,`image`) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
        if(err) return res.json({Error: "Error in hashing password"});
        const values = [
            req.body.name,
            req.body.phoneNo,
            req.body.email,
            req.body.password,
            req.body.address,
            req.file.filename
        ]
        con.query(sql, [values], (err, result) => {
            if(err) return res.json({Error: "Inside singup query"});
            return res.json({Status: "Success"});
        })
    })

})

app.get('/getResident', (req, res) => {
    const sql = "SELECT * FROM resident";
    con.query(sql, (err, result) => {
        if(err) return res.json({Error: "Get resident error in sql"});
        return res.json({Status: "Success", Result: result})
    })
})

app.get('/get/:id', (req, res) => {
    const id = req.params.id;
    const sql = "SELECT * FROM resident where id = ?";
    con.query(sql, [id], (err, result) => {
        if(err) return res.json({Error: "Get resident error in sql"});
        return res.json({Status: "Success", Result: result})
    })
})

app.put('/update/:id', (req, res) => {
    const id = req.params.id;
    const { name, address, phoneNo, password, email } = req.body;  
    const sql = "UPDATE resident SET name = ?, address = ?, phoneNo = ?, password = ?, email = ? WHERE id = ?";
    con.query(sql, [name, address, phoneNo, password, email, id], (err, result) => {
        if (err) {
            return res.json({ Error: "Update resident error in SQL" });
        }
        return res.json({ Status: "Success" });
    })
})

app.delete('/delete/:id', (req, res) => {
    const id = req.params.id;
    const sql = "Delete FROM resident WHERE id = ?";
    con.query(sql, [id], (err, result) => {
        if(err) return res.json({Error: "delete resident error in sql"});
        return res.json({Status: "Success"})
    })
})

app.listen(8081, () => {
    console.log("Running");
})