import mongoose from "mongoose"
import dns from "dns"

const connectDB = async () => {
    // Use Google DNS to resolve MongoDB Atlas SRV records
    dns.setServers(['8.8.8.8', '8.8.4.4'])

    mongoose.connection.on("connected", () => console.log("database connected"))
    mongoose.connection.on("error", (err) => console.log("database error:", err))

    await mongoose.connect(process.env.MONGODB_URI)
}

export default connectDB;