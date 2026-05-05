import { useState } from 'react';

export default function MovieCard({ movie }) {
  const [isAdding, setIsAdding] = useState(false); //[cite: 7]
  const [message, setMessage] = useState(''); //[cite: 7]

  // A film poszterének URL-je (A TMDB csak a fájlnevet adja vissza, ezt ki kell egészíteni)
  const imageUrl = movie.poster_path 
    ? `https://image.tmdb.org/t/p/w500${movie.poster_path}` 
    : 'https://via.placeholder.com/300x450/1f2937/ffffff?text=Nincs+Kép';

  // Kiolvassuk a TMDB-ből a megjelenési évet
  const releaseYear = movie.release_date ? movie.release_date.split('-')[0] : 'Ismeretlen év';

  const handleFavoriteClick = async () => { //[cite: 7]
    const token = localStorage.getItem('token'); //[cite: 3]
    
    if (!token) { //[cite: 3]
      alert("Kérlek jelentkezz be a kedvencekhez!"); //[cite: 3]
      return; //[cite: 3]
    }

    setIsAdding(true); //[cite: 7]
    setMessage(''); //[cite: 7]

    try {
      // Küldjük az adatot a TE backendnednek!
      const response = await fetch('http://localhost:5000/api/favorites', { //[cite: 3]
        method: 'POST', //[cite: 3]
        headers: { //[cite: 3]
          'Content-Type': 'application/json', //[cite: 3]
          'Authorization': `Bearer ${token}` //[cite: 3]
        },
        body: JSON.stringify({ //[cite: 3]
          movieId: movie.id, //[cite: 3, 7]
          title: movie.title, //[cite: 3, 7]
          poster_path: movie.poster_path, //[cite: 3]
          vote_average: movie.vote_average || 0 //[cite: 3]
        })
      });

      if (response.ok) { //[cite: 3]
        setMessage('Hozzáadva!'); //[cite: 7]
      } else {
        const data = await response.json(); //[cite: 3]
        setMessage(data.message || 'Már a kedvenced!'); // Ha már benne van az adatbázisban
      }
    } catch (error) { //[cite: 3, 7]
      console.error(error); //[cite: 7]
      setMessage('Hiba történt'); //[cite: 7]
    } finally { //[cite: 7]
      setIsAdding(false); //[cite: 7]
      setTimeout(() => { //[cite: 7]
        setMessage(''); //[cite: 7]
      }, 3000); //[cite: 7]
    }
  };

  return (
    <div className="flex flex-col overflow-hidden bg-gray-800 border border-gray-700 shadow-lg rounded-xl"> {/*[cite: 7] */}
      <img 
        src={imageUrl} 
        alt={movie.title} //[cite: 7]
        className="object-cover w-full h-72 bg-gray-700" //[cite: 7]
      />
      <div className="flex flex-col p-4 flex-grow"> {/*[cite: 7] */}
        <h3 className="mb-1 text-lg font-bold text-white truncate" title={movie.title}> {/*[cite: 7] */}
          {movie.title} {/*[cite: 7] */}
        </h3>
        <p className="mb-4 text-sm text-gray-400">{releaseYear}</p> {/*[cite: 7] */}
        
        {message && ( //[cite: 7]
          <p className="text-sm text-center mb-2 font-bold text-green-400">{message}</p> //[cite: 7]
        )}

        <div className="mt-auto"> {/*[cite: 7] */}
          <button 
            onClick={handleFavoriteClick} //[cite: 7]
            disabled={isAdding} //[cite: 7]
            className="w-full px-4 py-2 text-sm font-bold text-white bg-blue-600 rounded disabled:bg-gray-500" //[cite: 7]
          >
            {isAdding ? 'Töltés...' : 'Kedvencekhez'} {/*[cite: 7] */}
          </button>
        </div>
      </div>
    </div>
  );
}