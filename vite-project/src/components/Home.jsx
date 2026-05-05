import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import MovieCard from './MovieCard';

export default function Home() {
  const navigate = useNavigate();
  const [movies, setMovies] = useState([]); 
  const [searchTerm, setSearchTerm] = useState('');
  const [favoriteIds, setFavoriteIds] = useState([]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
    }
  }, [navigate]);

  useEffect(() => {
    const fetchUserFavorites = async () => {
      const token = localStorage.getItem('token');
      if (!token) return;

      try {
        const response = await fetch('http://localhost:5000/api/favorites', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
          const data = await response.json();
          setFavoriteIds(data.map(fav => fav.movieId));
        }
      } catch (error) {
        console.error("Hiba a kedvencek lekérésekor:", error);
      }
    };

    fetchUserFavorites();
  }, []);

  useEffect(() => {
    const fetchMovies = async () => {
      const url = searchTerm
        ? `https://api.themoviedb.org/3/search/movie?query=${searchTerm}&language=hu-HU`
        : 'https://api.themoviedb.org/3/movie/popular?language=hu-HU';

      try {
        const response = await fetch(url, {
          headers: {
            accept: 'application/json',
            Authorization: `Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIyZWE0NDQwYjEzN2JhYzhmYWUwOWFjZGMxZDM1YjZkYiIsIm5iZiI6MTc3NzUyODU3Ni4wOTUsInN1YiI6IjY5ZjJlZjAwODBkOGYwMmE4Mzg0MmU2MiIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.c_PbTnWIHp9IB8AKDjzANdHJdZUqMkuj7xzIjwy-MSE`
          }
        });
        const data = await response.json();
        setMovies(data.results || []);
      } catch (error) {
        console.error("Hiba a filmek betöltésekor:", error);
      }
    };

    const delayDebounceFn = setTimeout(() => {
      fetchMovies();
    }, 500);

    return () => clearTimeout(delayDebounceFn);
  }, [searchTerm]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white pb-10">
      <nav className="flex items-center justify-between p-4 bg-gray-800 shadow-md sticky top-0 z-10 gap-4">
        <h1 className="text-3xl font-bold text-blue-500 shrink-0">Filmtár</h1>

        <div className="flex-grow max-w-md mx-4">
          <input
            type="text"
            placeholder="Keresés a filmek között..."
            className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="flex gap-4 shrink-0">
          <button onClick={() => navigate('/favorites')} className="px-4 py-2 text-sm font-bold text-gray-300 hover:text-white">
            Kedvenceim
          </button>
          <button onClick={handleLogout} className="px-4 py-2 text-sm font-bold text-white bg-red-600 rounded-lg hover:bg-red-700">
            Kijelentkezés
          </button>
        </div>
      </nav>

      <main className="p-8 max-w-7xl mx-auto">
        <h2 className="text-2xl font-semibold mb-6 border-b border-gray-700 pb-2">
          {searchTerm ? `Találatok a következőre: "${searchTerm}"` : 'Népszerű filmek'}
        </h2>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6">
          {movies.length > 0 ? (
            movies.map((movie) => (
              <MovieCard
                key={movie.id}
                movie={movie}
                isAlreadyFavorite={favoriteIds.includes(movie.id)}
              />
            ))
          ) : (
            <p className="col-span-full text-center text-gray-500 mt-10">Nincs a keresésnek megfelelő film...</p>
          )}
        </div>
      </main>
    </div>
  );
}