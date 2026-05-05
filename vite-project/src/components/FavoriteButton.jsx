import React, { useState, useEffect } from 'react';

const FavoriteButton = ({ movie }) => {
    const [isFavorite, setIsFavorite] = useState(false);
    // Feltételezzük, hogy a token a localStorage-ban van tárolva bejelentkezés után
    const token = localStorage.getItem('token'); 

    // Opcionális: lekérdezni, hogy a film már kedvenc-e (hogy a szív ikon piros legyen)
    // Ezt érdemes egy felsőbb szintű komponensben lekérni (összes kedvenc lekérése), 
    // és prop-ként átadni, de itt a példa kedvéért bemutatom az elvet.

    const toggleFavorite = async () => {
        if (!token) {
            alert("Kérlek jelentkezz be a kedvencekhez!");
            return;
        }

        try {
            if (isFavorite) {
                // TÖRLÉS A KEDVENCEKBŐL
                const response = await fetch(`http://localhost:5000/api/favorites/${movie.id}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (response.ok) {
                    setIsFavorite(false);
                    console.log("Törölve a kedvencekből");
                }
            } else {
                // HOZZÁADÁS A KEDVENCEKHEZ
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
                        vote_average: movie.vote_average
                    })
                });

                if (response.ok) {
                    setIsFavorite(true);
                    console.log("Hozzáadva a kedvencekhez");
                } else {
                    const data = await response.json();
                    alert(data.message);
                }
            }
        } catch (error) {
            console.error("Hiba történt a kedvencek módosításakor:", error);
        }
    };

    return (
        <button onClick={toggleFavorite} style={{ cursor: 'pointer' }}>
            {isFavorite ? '❤️ Törlés' : '🤍 Kedvencekbe'}
        </button>
    );
};

export default FavoriteButton;