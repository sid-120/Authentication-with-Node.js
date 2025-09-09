import mongoose from "mongoose";

const connectDB = async () => {
  mongoose.connection.on("connected", () =>
    console.log("MongoDB Database connected")
  );

  await mongoose.connect(`${process.env.MONGODB_URL}/mern-auth`);
};

export default connectDB;
