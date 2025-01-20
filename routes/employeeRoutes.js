//routes/employeeRoutes.js
import express from "express";
import {
  getEmployees,
  createEmployee,
  updateEmployee,
  deleteEmployee,
  getEmployeeByEmail,
} from "../controllers/employeeController.js";
import userAuth from "../middleware/userAuth.js";

const employeeRouter = express.Router();

// Routes
employeeRouter.get("/get-employees", userAuth, getEmployees); // Get all employees
employeeRouter.post("/email", getEmployeeByEmail); // Get employee by email
employeeRouter.post("/create-employee", userAuth, createEmployee); // Create a new employee
employeeRouter.put("/:id", userAuth, updateEmployee); // Update an employee
employeeRouter.delete("/:id", userAuth, deleteEmployee); // Delete an employee

export default employeeRouter;


