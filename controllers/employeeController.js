//controllers/employeeController.js
import employeeModel from "../models/employeeModel.js";

// Get all employees
export const getEmployees = async (req, res) => {
  try {
    const employees = await employeeModel.find();
    res.status(200).json({ success: true, data: employees });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get employee by email
export const getEmployeeByEmail = async (req, res) => {
  try {
    // const { email } = req.query; 
    const { email } = req.body;  // Get email from the request body
    const employee = await employeeModel.findOne({ email });

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    if (!employee) {
      return res.json({ success: false, message: 'Employee not found' });
    }

    res.status(200).json({ success: true, data: employee });
  } catch (error) {
    console.error('Error fetching employee by email:', error); // Log error
    res.status(500).json({ success: false, message: error.message });
  }
};


// Create a new employee
export const createEmployee = async (req, res) => {
  try {
    const { name, email, position, department, salary, phone, address, city } = req.body;
    const newEmployee = new employeeModel({
      name,
      email,
      position,
      department,
      salary,
      phone,
      address,
      city,
    });

    await newEmployee.save();
    res.status(201).json({ success: true, data: newEmployee });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Update an employee
export const updateEmployee = async (req, res) => {
  try {
    const { id } = req.params;
    const updatedData = req.body;

    const employee = await employeeModel.findByIdAndUpdate(id, updatedData, {
      new: true,
      runValidators: true,
    });

    if (!employee) {
      return res.status(404).json({ success: false, message: "Employee not found" });
    }

    res.status(200).json({ success: true, data: employee });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Delete an employee
export const deleteEmployee = async (req, res) => {
  try {
    const { id } = req.params;
    const employee = await employeeModel.findByIdAndDelete(id);

    if (!employee) {
      return res.status(404).json({ success: false, message: "Employee not found" });
    }

    res.status(200).json({ success: true, message: "Employee deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

