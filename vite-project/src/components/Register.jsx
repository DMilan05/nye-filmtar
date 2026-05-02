import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { registerUser } from '../services/authService';

export default function Register() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await registerUser(username, email, password);
      alert('Sikeres regisztráció! Kérlek, jelentkezz be.');
      navigate('/login');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-900">
      <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-xl shadow-lg text-white">
        <h2 className="text-3xl font-bold text-center">Regisztráció</h2>
        {error && <div className="p-3 text-red-500 bg-red-100 rounded-lg">{error}</div>}
        
        <form className="space-y-4" onSubmit={handleSubmit}>
          <input type="text" placeholder="Felhasználónév" required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" value={username} onChange={(e) => setUsername(e.target.value)} />
          <input type="email" placeholder="Email cím" required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" value={email} onChange={(e) => setEmail(e.target.value)} />
          <input type="password" placeholder="Jelszó" required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" value={password} onChange={(e) => setPassword(e.target.value)} />
          <button type="submit" className="w-full px-4 py-2 font-bold text-white bg-blue-600 rounded-lg hover:bg-blue-700">Regisztrálok</button>
        </form>
        <p className="text-center text-gray-400">Már van fiókod? <Link to="/login" className="text-blue-400 hover:underline">Jelentkezz be!</Link></p>
      </div>
    </div>
  );
}