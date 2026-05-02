import { useState } from 'react';
import { addToFavorites } from '../services/favoritesService'; 

export default function MovieCard({ movie }) {
  const [isAdding, setIsAdding] = useState(false);
  const [message, setMessage] = useState(''); 

  const handleFavoriteClick = async () => {
    setIsAdding(true);
    setMessage('');

    try {
      await addToFavorites({
        tmdbId: movie.id, 
        title: movie.title,
        year: movie.year,
        poster: movie.poster
      });
      
      setMessage('Hozzáadva!');
    } catch (error) {
      console.error(error);
      setMessage('Hiba történt');
    } finally {
      setIsAdding(false);
      
      setTimeout(() => {
        setMessage('');
      }, 3000);
    }
  };

  return (
    <div className="flex flex-col overflow-hidden bg-gray-800 border border-gray-700 shadow-lg rounded-xl">
      
      {/* Film poszter */}
      <img 
        src={movie.poster} 
        alt={movie.title} 
        className="object-cover w-full h-72 bg-gray-700"
      />
      
      {/* Film adatai */}
      <div className="flex flex-col p-4 flex-grow">
        <h3 className="mb-1 text-lg font-bold text-white truncate" title={movie.title}>
          {movie.title}
        </h3>
        <p className="mb-4 text-sm text-gray-400">{movie.year}</p>
        
        {message && (
          <p className="text-sm text-center mb-2 font-bold text-green-400">{message}</p>
        )}

        <div className="mt-auto">
          <button 
            onClick={handleFavoriteClick}
            disabled={isAdding} 
            className="w-full px-4 py-2 text-sm font-bold text-white bg-blue-600 rounded disabled:bg-gray-500"
          >
            {isAdding ? 'Töltés...' : 'Kedvencekhez'}
          </button>
        </div>

      </div>
    </div>
  );
}