import express from 'express';


const login = async(req,res) => {
    const {login,pass} = req.body;

    if(!login || !pass){
        return res.status(400).json({message:"Login and password are required"});
    }
    
    return res.status(200).json({message:"Login successful"});
}