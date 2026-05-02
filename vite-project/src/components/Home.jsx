import { useState } from 'react'; 
import { useNavigate } from 'react-router-dom';
import MovieCard from './MovieCard';

const mockMovies = [
  { id: 1, title: 'A sötét lovag', year: '2008', poster: 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Batman' },
  { id: 2, title: 'Csillagok között', year: '2014', poster: 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Interstellar' },
  { id: 3, title: 'Eredet', year: '2010', poster: 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Inception' },
  { id: 4, title: 'Dűne', year: '2021', poster: 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Dune' },
  { id: 5, title: 'Mátrix', year: '1999', poster: 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Matrix' },
  { id: 6, title: 'Ponyvaregény', year: '1994', poster: 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Pulp+Fiction' },
];

export default function Home() {
  const navigate = useNavigate();
  
  const [searchTerm, setSearchTerm] = useState('');

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  const filteredMovies = mockMovies.filter((movie) =>
    movie.title.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-900 text-white pb-10">
      {/* Fejléc */}
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
          {filteredMovies.length > 0 ? (
            filteredMovies.map((movie) => (
              <MovieCard key={movie.id} movie={movie} />
            ))
          ) : (
            <p className="col-span-full text-center text-gray-500 mt-10">Nincs a keresésnek megfelelő film...</p>
          )}
        </div>
      </main>
    </div>
  );
}