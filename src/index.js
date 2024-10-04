import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import cipherRoutes from './routes/cipherRoutes.js';

const app = express();

app.use(cors());

app.use(bodyParser.json());

app.use('/api', cipherRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
