import React, { useState } from 'react';
import Home from './pages/Home/home.jsx'
import { TextField } from '@mui/material'
import '../startup/client/routes.jsx'

export const Hello = () => {
  const [counter, setCounter] = useState(0);

  const increment = () => {
    setCounter(counter + 1);
  };

  return (
      <Home />
  );
};
