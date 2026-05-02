import { useNavigate } from 'react-router-dom';

export default function Favorites() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Fejléc */}
      <nav className="flex items-center justify-between p-4 bg-gray-800 shadow-md sticky top-0 z-10">
        <h1 className="text-3xl font-bold text-blue-500">Filmtár</h1>
        <button
          onClick={() => navigate('/')}
          className="px-4 py-2 text-sm font-bold text-gray-300 hover:text-white"
        >
          Vissza a filmekhez
        </button>
      </nav>

      {/* Tartalom */}
      <main className="p-8 max-w-7xl mx-auto">
        <h2 className="text-2xl font-semibold mb-6 border-b border-gray-700 pb-2">
          Kedvenc filmjeim
        </h2>
        
        {/* Ideiglenes üzenet, amíg nincs backend */}
        <div className="p-8 text-center border border-gray-700 rounded-xl bg-gray-800 mt-10">
          <p className="text-gray-400 text-lg">
            A kedvencek listája még üres, vagy az adatbázis nem elérhető.
          </p>
        </div>
      </main>
    </div>
  );
}