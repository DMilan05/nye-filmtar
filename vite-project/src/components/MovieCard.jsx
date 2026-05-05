import { useState } from 'react';

export default function MovieCard({ movie }) {
  const [isAdding, setIsAdding] = useState(false); 
  const [message, setMessage] = useState(''); 

  const imageUrl = movie.poster_path 
    ? `https://image.tmdb.org/t/p/w500${movie.poster_path}` 
    : 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Nincs+Kép';

  const releaseYear = movie.release_date ? movie.release_date.split('-')[0] : 'Ismeretlen év';

  const handleFavoriteClick = async () => { 
    const token = localStorage.getItem('token'); 
    
    if (!token) { 
      alert("Kérlek jelentkezz be a kedvencekhez!"); 
      return; 
    }

    setIsAdding(true); 

    try {
      const response = await fetch('http://localhost:5000/api/favorites', { 
        method: 'POST', 
        headers: { 
          'Content-Type': 'application/json', 
          'Authorization': `Bearer ${token}` 
        },
        body: JSON.stringify({ 
          movieId: movie.id, 
          title: movie.title, 
          poster_path: movie.poster_path, 
          vote_average: movie.vote_average || 0 
        })
      });

      if (response.ok) { 
        setMessage('Hozzáadva!'); 
      } else {
        const data = await response.json(); 
        setMessage(data.message || 'Már a kedvenced!'); 
      }
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
      <img 
        src={imageUrl} 
        alt={movie.title} 
        className="object-cover w-full h-72 bg-gray-700" 
      />
      <div className="flex flex-col p-4 flex-grow"> 
        <h3 className="mb-1 text-lg font-bold text-white truncate" title={movie.title}> 
          {movie.title} 
        </h3>
        <p className="mb-4 text-sm text-gray-400">{releaseYear}</p> 
        
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