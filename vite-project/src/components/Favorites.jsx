import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom'; //[cite: 4]
import MovieCard from './MovieCard'; // Újrahasznosítjuk a kártyát!

export default function Favorites() {
  const navigate = useNavigate(); //[cite: 4]
  const [favorites, setFavorites] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFavorites = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/login'); // Ha nincs belépve, kidobjuk
        return;
      }

      try {
        // Lekérjük a te saját backendedről a felhasználó kedvenceit
        const response = await fetch('http://localhost:5000/api/favorites', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        
        if (response.ok) {
          const data = await response.json();
          // Mivel az adatbázisban a TMDB adatokat mentettük el (title, poster_path, stb), 
          // a MovieCard tökéletesen meg fogja tudni jeleníteni őket!
          setFavorites(data);
        }
      } catch (error) {
        console.error("Hiba a kedvencek letöltésekor:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchFavorites();
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gray-900 text-white"> {/*[cite: 4] */}
      <nav className="flex items-center justify-between p-4 bg-gray-800 shadow-md sticky top-0 z-10"> {/*[cite: 4] */}
        <h1 className="text-3xl font-bold text-blue-500">Filmtár</h1> {/*[cite: 4] */}
        <button
          onClick={() => navigate('/')} //[cite: 4]
          className="px-4 py-2 text-sm font-bold text-gray-300 hover:text-white" //[cite: 4]
        >
          Vissza a filmekhez {/*[cite: 4] */}
        </button>
      </nav>

      <main className="p-8 max-w-7xl mx-auto"> {/*[cite: 4] */}
        <h2 className="text-2xl font-semibold mb-6 border-b border-gray-700 pb-2"> {/*[cite: 4] */}
          Kedvenc filmjeim {/*[cite: 4] */}
        </h2>
        
        {loading ? (
          <p className="text-center text-gray-400 mt-10">Betöltés...</p>
        ) : favorites.length > 0 ? (
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6">
            {favorites.map((movie) => (
              <MovieCard key={movie._id} movie={movie} /> 
            ))}
          </div>
        ) : (
          <div className="p-8 text-center border border-gray-700 rounded-xl bg-gray-800 mt-10"> {/*[cite: 4] */}
            <p className="text-gray-400 text-lg"> {/*[cite: 4] */}
              A kedvencek listája még üres. Keress egy jó filmet a főoldalon! {/*[cite: 4] */}
            </p>
          </div>
        )}
      </main>
    </div>
  );
}