import express, { json, urlencoded } from 'express';
import session from 'express-session';
import exphbs from 'express-handlebars';
import path, { join } from 'path';
import bcrypt from 'bcrypt'
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy } from 'passport-local';
import mongoose from 'mongoose';
import * as model from './usuarios.js'
import Contenedor from './contenedores/ContenedorProductos.js';

const productosApi = new Contenedor('productos.json')

async function addUser(usuario) {
    try {
        const URL = 'mongodb://localhost:27017/usuariosEntregable11';
        mongoose.connect(URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        console.log('Base de datos conectada');

        const user = usuario

        const userSave = new model.users(user);
        const savedUser = await userSave.save();
        console.log(savedUser, 'dentro de addUser()')
    } catch (error) {
        console.log(error)
    }
}

async function readUser(usuario) {
    try {
        const URL = 'mongodb://localhost:27017/usuariosEntregable11';
        mongoose.connect(URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        console.log('Base de datos conectada');
        const userRead = await model.users.findOne({email: usuario})
        console.log(userRead, 'leido desde DB mongo')
        return userRead
    } catch (error) {
        
    }
}

const LocalStrategy = Strategy;

dotenv.config()

const app = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}))

passport.use(new LocalStrategy(
    async function (username, password, done)
    {
        const existeUsuario = await readUser(username)
        if(!existeUsuario) {
            return done(null, false)
        } else {
            const match = await verifyPass(existeUsuario, password)

            if(!match) {
                return done(null, false)
            }
            return done(null, existeUsuario)
        }
    }
))

passport.serializeUser((usuario, done) => {
    done(null, usuario.email)
})

passport.deserializeUser(async (email, done) => {
    const existeUsuario = await readUser(email);
    done(null, existeUsuario)
})

app.set('views', 'src/views');
app.engine('.hbs', exphbs.engine({
    defaultLayout: 'main',
    layoutsDir: path.join(app.get('views'), 'layouts'),
    extname: '.hbs'
}));
app.set('view engine', '.hbs')

function isAuth(req, res, next) {
    if(req.isAuthenticated()) {
        next()
    } else {
        res.redirect('/login')
    }
}

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 600000
    }
}))

app.use(passport.initialize());
app.use(passport.session())

async function generateHashPassword(password) {
    const hashPassword = await bcrypt.hash(password, 10)
    return hashPassword
}

async function verifyPass(usuario, password) {
    const match = await bcrypt.compare(password, usuario.password)
    console.log(`pass login: ${password} || pass hash: ${usuario.password}`)
    return match
}

app.get('/', (req, res) => {
    res.redirect('login')
})

app.get('/login', (req, res) => {
    res.render('login.hbs')
})

app.get('/register', (req, res) => {
    res.render('register.hbs')
})

app.post('/login', passport.authenticate('local', {successRedirect: '/datos', failureRedirect: '/login-error'}))

app.get('/datos', isAuth, async (req, res) => {
    const datosUsuario = {
        email: req.user.email
    }
    const products = await productosApi.getAll()
    res.render('datos', {datos: datosUsuario, products: products})
    

})

app.post('/datos', async(req, res) => {
    const nuevoProducto = req.body;
    const result = await productosApi.save(nuevoProducto);
    res.redirect('/datos')
})

app.post('/register', async (req, res) => {
    const {email, password} = req.body;
    const newUsuario = await readUser(email)
    if(newUsuario) {
        res.render('register-error')
    } else {
        const newUser = {email, password: await generateHashPassword(password)}
        addUser(newUser)
        res.redirect('/login')
    }
})

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if(err) {
            throw err
        }
        res.redirect('/login')
    })
})

app.get('/login-error', (req, res) => {
    res.render('login-error')
})

const PORT = process.env.PORT;
const server = app.listen(PORT, () => {
    console.log(`Servidor escuchando en puerto ${PORT}`);
})
server.on('error', error => {
    console.error(`Error en el servidor ${error}`);
});