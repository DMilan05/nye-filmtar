const express = require('express');
const router = express.Router();
const Favorite = require('../models/Favorite');
const verifyToken = require('../middleware/verifyToken');

router.get('/', verifyToken, async (req, res) => {
    try {
        const favorites = await Favorite.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.status(200).json(favorites);
    } catch (err) {
        res.status(500).json({ message: "Hiba a lekérdezés során.", error: err.message });
    }
});

router.post('/', verifyToken, async (req, res) => {
    try {
        const { movieId, title, poster_path, vote_average } = req.body;

        const existingFavorite = await Favorite.findOne({ user: req.user.id, movieId: movieId });
        if (existingFavorite) {
            return res.status(400).json({ message: 'Ez a film már a kedvenceid között van!' });
        }

        const newFavorite = new Favorite({
            user: req.user.id,
            movieId,
            title,
            poster_path,
            vote_average
        });

        const savedFavorite = await newFavorite.save();
        res.status(201).json(savedFavorite);
    } catch (err) {
        res.status(500).json({ message: "Hiba a mentés során.", error: err.message });
    }
});

router.delete('/:movieId', verifyToken, async (req, res) => {
    try {
        const deletedFavorite = await Favorite.findOneAndDelete({
            user: req.user.id,
            // ITT A JAVÍTÁS: Számmá alakítjuk a movieId-t, mert az URL-ből szövegként érkezik
            movieId: Number(req.params.movieId)
        });

        if (!deletedFavorite) {
            return res.status(404).json({ message: 'A film nem található a kedvencek között.' });
        }

        res.status(200).json({ message: 'Sikeresen törölve a kedvencekből!' });
    } catch (err) {
        res.status(500).json({ message: "Hiba a törlés során.", error: err.message });
    }
});

module.exports = router;