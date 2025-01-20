//models/employeeModel.js
import mongoose from "mongoose";
const employeeSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { 
        type: String, 
        required: true, 
        unique: true, 
        lowercase: true
    },
    position: { type: String, required: true },
    department: { type: String, default: "" },
    salary:{type: Number, default:0, min:0},
    dateOfJoining: { 
        type: Date, 
        default: Date.now // Store when the employee joined
      },
    phone:{type: String, trim: true, default: ""},
    address: {type: String, default: ""},
    city:{type: String, default: ""}
});

const employeeModel = mongoose.models.employee || mongoose.model("employee", employeeSchema);

export default employeeModel;