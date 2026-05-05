import { useState, useEffect } from 'react'; //[cite: 5]
import { useNavigate } from 'react-router-dom'; //[cite: 5]
import MovieCard from './MovieCard'; //[cite: 5]

export default function Home() {
  const navigate = useNavigate(); //[cite: 5]
  const [movies, setMovies] = useState([]); 
  const [searchTerm, setSearchTerm] = useState(''); //[cite: 5]

  // Ez a fv hívja meg a TMDB API-t
  useEffect(() => {
    const fetchMovies = async () => {
      // Ha van keresőszó, akkor keresünk, ha nincs, akkor a legnépszerűbbeket kérjük le
      const url = searchTerm 
        ? `https://api.themoviedb.org/3/search/movie?query=${searchTerm}&language=hu-HU`
        : 'https://api.themoviedb.org/3/movie/popular?language=hu-HU';

      try {
        const response = await fetch(url, {
          headers: {
            accept: 'application/json',
            // Itt használjuk a .env fájlba tett tokenedet!
            Authorization: `Bearer ${import.meta.env.VITE_TMDB_BEARER_TOKEN}` 
          }
        });
        const data = await response.json();
        setMovies(data.results || []); // Frissítjük az állapotot a letöltött filmekkel
      } catch (error) {
        console.error("Hiba a filmek betöltésekor:", error);
      }
    };

    // Egy kis késleltetés (debounce), hogy ne küldjön kérést minden egyes leütött betűnél
    const delayDebounceFn = setTimeout(() => {
      fetchMovies();
    }, 500);

    return () => clearTimeout(delayDebounceFn);
  }, [searchTerm]);

  const handleLogout = () => { //[cite: 5]
    localStorage.removeItem('token'); //[cite: 5]
    navigate('/login'); //[cite: 5]
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white pb-10"> {/*[cite: 5] */}
      <nav className="flex items-center justify-between p-4 bg-gray-800 shadow-md sticky top-0 z-10 gap-4"> {/*[cite: 5] */}
        <h1 className="text-3xl font-bold text-blue-500 shrink-0">Filmtár</h1> {/*[cite: 5] */}

        <div className="flex-grow max-w-md mx-4"> {/*[cite: 5] */}
          <input
            type="text" //[cite: 5]
            placeholder="Keresés a filmek között..." //[cite: 5]
            className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white" //[cite: 5]
            value={searchTerm} //[cite: 5]
            onChange={(e) => setSearchTerm(e.target.value)} //[cite: 5]
          />
        </div>

        <div className="flex gap-4 shrink-0"> {/*[cite: 5] */}
          <button onClick={() => navigate('/favorites')} className="px-4 py-2 text-sm font-bold text-gray-300 hover:text-white"> {/*[cite: 5] */}
            Kedvenceim {/*[cite: 5] */}
          </button>
          <button onClick={handleLogout} className="px-4 py-2 text-sm font-bold text-white bg-red-600 rounded-lg hover:bg-red-700"> {/*[cite: 5] */}
            Kijelentkezés {/*[cite: 5] */}
          </button>
        </div>
      </nav>

      <main className="p-8 max-w-7xl mx-auto"> {/*[cite: 5] */}
        <h2 className="text-2xl font-semibold mb-6 border-b border-gray-700 pb-2"> {/*[cite: 5] */}
          {searchTerm ? `Találatok a következőre: "${searchTerm}"` : 'Népszerű filmek'} {/*[cite: 5] */}
        </h2>
        
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6"> {/*[cite: 5] */}
          {movies.length > 0 ? ( //[cite: 5]
            movies.map((movie) => ( //[cite: 5]
              <MovieCard key={movie.id} movie={movie} /> //[cite: 5]
            ))
          ) : (
            <p className="col-span-full text-center text-gray-500 mt-10">Nincs a keresésnek megfelelő film...</p> //[cite: 5]
          )}
        </div>
      </main>
    </div>
  );
}