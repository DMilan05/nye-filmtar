const mongoose = require('mongoose');

const favoriteSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },

    movieId: {
        type: Number,
        required: true
    },

    title: {
        type: String,
        required: true
    },
    poster_path: {
        type: String
    },
    vote_average: {
        type: Number
    },
    release_date: {
        type: String
    }
}, { timestamps: true });

module.exports = mongoose.model('Favorite', favoriteSchema);