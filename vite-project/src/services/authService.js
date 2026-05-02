const API_URL = 'http://localhost:5000/api/auth';

export const registerUser = async (username, email, password) => {
  const response = await fetch(`${API_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'Hiba a regisztráció során!');
  return data;
};

export const loginUser = async (email, password) => {
  const response = await fetch(`${API_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'Hiba a bejelentkezés során!');
  
  if (data.token) {
    localStorage.setItem('token', data.token); // Eltároljuk a tokent a későbbi hívásokhoz
  }
  return data;
};