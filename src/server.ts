import dotenv from 'dotenv';
import app from './app';
import connectDB from './config/db';

// connect to database
connectDB();

dotenv.config();
const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
