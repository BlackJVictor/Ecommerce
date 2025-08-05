import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();


if(!process.env.MONGODB_URI) {
    throw new Error('ESTA STRING DE CONEXÃO DO BANCO DE DADOS NAO ESTA NO ARQUIVO .ENV');
}

async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGODB_URI,);
        console.log('Conectado ao banco de dados com sucesso');
    } catch (error) {
        console.log('Erro ao conectar ao banco de dados', error);
        process.exit(1);
    }
}

export default connectDB;