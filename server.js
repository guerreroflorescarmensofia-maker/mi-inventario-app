const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const port = 3000;

const MONGODB_URI = 'mongodb+srv://guerreroflorescarmensofia_db_user:U2J8HUc5m1o7nee4@groflo.ysyzpq2.mongodb.net/?retryWrites=true&w=majority&appName=GROFLO';
const jwtSecret = 'mi_clave_secreta_super_segura';

app.use(express.json());
app.use(cors());

mongoose.connect(MONGODB_URI)
  .then(() => console.log('Base de datos conectada correctamente'))
  .catch(err => console.error('Error de conexión a la base de datos:', err));

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Token no proporcionado.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido o expirado.' });
        }
        req.user = user;
        next();
    });
}

const productoSchema = new mongoose.Schema({
  nombre: String,
  precioVenta: Number,
  precioCompra: Number,
  codigoBarras: String,
  stock: { type: Number, default: 0 }
});
const Producto = mongoose.model('Producto', productoSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

const ventaSchema = new mongoose.Schema({
    nombreProducto: String,
    cantidad: Number,
    ganancia: Number,
    fecha: { type: Date, default: Date.now },
});
const Venta = mongoose.model('Venta', ventaSchema);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        const newUser = new User({
            username,
            password: hashedPassword,
        });
        await newUser.save();

        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (err) {
        res.status(400).json({ message: 'Error al registrar el usuario: ' + err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: '1h' });

        res.status(200).json({ token, message: 'Inicio de sesión exitoso.' });
    } catch (err) {
        res.status(500).json({ message: 'Error del servidor: ' + err.message });
    }
});

app.post('/api/articulos', authenticateToken, async (req, res) => {
    try {
        const nuevoArticulo = new Producto(req.body);
        await nuevoArticulo.save();
        res.status(201).json(nuevoArticulo);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.get('/api/articulos', authenticateToken, async (req, res) => {
    try {
        const articulos = await Producto.find();
        res.status(200).json(articulos);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/articulos/:id', authenticateToken, async (req, res) => {
    try {
        const articulo = await Producto.findById(req.params.id);
        if (!articulo) {
            return res.status(404).json({ message: 'Artículo no encontrado.' });
        }
        res.status(200).json(articulo);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/api/articulos/:id', authenticateToken, async (req, res) => {
    try {
        const articuloActualizado = await Producto.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.status(200).json(articuloActualizado);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

app.delete('/api/articulos/:id', authenticateToken, async (req, res) => {
    try {
        await Producto.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: 'Artículo eliminado exitosamente' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/ventas', authenticateToken, async (req, res) => {
    try {
        const { productoId, cantidad } = req.body;

        const producto = await Producto.findById(productoId);
        if (!producto) {
            return res.status(404).json({ message: 'Producto no encontrado.' });
        }

        if (producto.stock < cantidad) {
            return res.status(400).json({ message: `No hay suficiente stock para ${producto.nombre}. Stock actual: ${producto.stock}` });
        }

        producto.stock -= cantidad;
        await producto.save();

        const ganancia = (producto.precioVenta - producto.precioCompra) * cantidad;
        const nuevaVenta = new Venta({
            nombreProducto: producto.nombre,
            cantidad: cantidad,
            ganancia: ganancia,
        });
        await nuevaVenta.save();

        res.status(201).json({ message: 'Venta registrada y stock actualizado exitosamente', venta: nuevaVenta });
    } catch (err) {
        res.status(500).json({ message: 'Error al registrar la venta: ' + err.message });
    }
});

app.get('/api/ventas', authenticateToken, async (req, res) => {
    try {
        const ventas = await Venta.find().sort({ fecha: -1 });
        res.status(200).json(ventas);
    } catch (err) {
        res.status(500).json({ message: 'Error al obtener las ventas: ' + err.message });
    }
});

app.delete('/api/ventas/:id', authenticateToken, async (req, res) => {
    try {
        await Venta.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: 'Venta eliminada exitosamente' });
    } catch (err) {
        res.status(500).json({ message: 'Error al eliminar la venta: ' + err.message });
    }
});

app.delete('/api/ventas', authenticateToken, async (req, res) => {
    try {
        await Venta.deleteMany({});
        res.status(200).json({ message: 'Historial de ventas borrado exitosamente' });
    } catch (err) {
        res.status(500).json({ message: 'Error al borrar el historial: ' + err.message });
    }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});