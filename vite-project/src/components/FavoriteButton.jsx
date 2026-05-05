import React, { useState, useEffect } from 'react';

const FavoriteButton = ({ movie }) => {
    const [isFavorite, setIsFavorite] = useState(false);
    const token = localStorage.getItem('token'); 



    const toggleFavorite = async () => {
        if (!token) {
            alert("Kérlek jelentkezz be a kedvencekhez!");
            return;
        }

        try {
            if (isFavorite) {
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
            {isFavorite ? 'Törlés' : 'Kedvencekbe'}
        </button>
    );
};

export default FavoriteButton;