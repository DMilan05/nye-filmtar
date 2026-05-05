const API_URL = 'http://localhost:5000/api/favorites';

const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };
};

export const addToFavorites = async (movieData) => {
  const response = await fetch(`${API_URL}`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(movieData),
  });
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || 'Nem sikerült hozzáadni a kedvencekhez.');
  }
  
  return response.json();
};

export const removeFromFavorites = async (movieId) => {
  const response = await fetch(`${API_URL}/remove/${movieId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  
  if (!response.ok) {
    throw new Error('Nem sikerült törölni a kedvencek közül.');
  }
  
  return response.json();
};