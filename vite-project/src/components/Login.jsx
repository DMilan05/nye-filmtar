import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { loginUser } from '../services/authService';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await loginUser(email, password);
      navigate('/'); 
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-900">
      <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-xl shadow-lg text-white">
        <h2 className="text-3xl font-bold text-center">Bejelentkezés</h2>
        {error && <div className="p-3 text-red-500 bg-red-100 rounded-lg">{error}</div>}
        
        <form className="space-y-4" onSubmit={handleSubmit}>
          <input type="email" placeholder="Email cím" required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" value={email} onChange={(e) => setEmail(e.target.value)} />
          <input type="password" placeholder="Jelszó" required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:ring-blue-500 focus:border-blue-500" value={password} onChange={(e) => setPassword(e.target.value)} />
          <button type="submit" className="w-full px-4 py-2 font-bold text-white bg-green-600 rounded-lg hover:bg-green-700">Belépés</button>
        </form>
        <p className="text-center text-gray-400">Nincs még fiókod? <Link to="/register" className="text-blue-400 hover:underline">Regisztrálj!</Link></p>
      </div>
    </div>
  );
}