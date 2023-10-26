import React, { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Logout } from '../services/Apis';
const Dashboard = () => {

  const navigate = useNavigate();

  const userValid = () => {
    let token = localStorage.getItem("token");
    if (token) {
      console.log("user valid")
    } else {
      navigate("*")
    }
  }

  useEffect(() => {
    userValid();
  })
  const handleLogout = async (e) => {
    e.preventDefault();
    localStorage.removeItem('token');

    const response = await Logout();

    if (response.status === 200) {
      navigate('/');
    }
  }

  return (
    <div>Dashboard

      <button className='btn btn-danger' onClick={handleLogout}>logout</button>
    </div>
  )
}

export default Dashboard