# Nye-Filmtár

Ez egy full-stack webalkalmazás, amelyet egyetemi vizsgaprojektként fejlesztettünk. Az alkalmazás segítségével a felhasználók böngészhetnek a legnépszerűbb filmek között a TMDB API-n keresztül, biztonságosan regisztrálhatnak és bejelentkezhetnek, valamint kezelhetik a saját kedvenc filmjeik listáját.

A fejlesztés résztvevői:
- Fehér Vivien Fanni
- Bálint László
- Dobos Milán Imre
  
## Funkciók
*   **Felhasználói azonosítás:** Biztonságos regisztráció és bejelentkezés JWT (JSON Web Tokens) és bcrypt jelszótitkosítás használatával.
*   **Filmek böngészése:** Népszerű filmek és keresési találatok dinamikus lekérése a külső TMDB API-ból.
*   **Kedvencek kezelése:** A bejelentkezett felhasználók egy gombnyomással hozzáadhatják a filmeket a saját profiljukhoz, és törölhetik is azokat.
*   **Reszponzív UI:** React és Tailwind CSS alapokon nyugvó modern, mobilbarát felület.

## Használt technológiák
*   **Frontend:** React.js (Vite), React Router, Tailwind CSS
*   **Backend:** Node.js, Express.js
*   **Adatbázis:** MongoDB (Mongoose)
*   **Külső API:** TMDB (The Movie Database) API

##  Telepítés és futtatás

### 1. Backend beállítása
1. Lépj be a `backend` mappába a terminálban.
2. Futtasd az `npm install` parancsot a szükséges csomagok letöltéséhez.
3. Hozz létre egy `.env` fájlt a backend gyökérmappájában az alábbi változókkal:
   ```env
   PORT=5000
   MONGO_URI=ide_jon_a_mongodb_kapcsolati_linked
   JWT_SECRET=ide_jon_a_titkos_kulcs
   
Indítsd el a szervert az npm start (vagy npm run dev) paranccsal. (Alapértelmezetten a http://localhost:5000 címen fut).

2. Frontend beállítása
Lépj be a frontend mappába (vagy aminek elnevezted a React projektet).

Futtasd az npm install parancsot a függőségek telepítéséhez.

Indítsd el a fejlesztői szervert az npm run dev paranccsal. (Alapértelmezetten a http://localhost:5173 címen fut).

Mesterséges intelligencia (AI) használata
A feladatkiírásnak megfelelően jelezzük, hogy a projekt fejlesztése során AI asszisztenst (Gemini 3.1 Pro) is igénybe vettünk támogató eszközként. Elsősorban a következő munkafolyamatoknál használtuk:

- Fájlstruktúra felállítása.
- Frontend igényessé tétele.
- A backend és frontend egyesítése.
- Hibakezelés.
- Eszközök javaslása (MongoDB, The Movie DB stb.)

Az alap kódstruktúra felépítése és a React/Node.js környezetek összehangolása.

Specifikus hibák felderítése és javítása (pl. Express útválasztási konfliktusok, típuseltérések javítása az azonosítóknál, vagy a Token Header kommunikáció problémái a frontend és a backend között).

A felhasználói felület finomhangolása a Tailwind CSS osztályok segítségével.

Az alkalmazás üzleti logikáját, az architekturális döntéseket és az adatbázis-integrációt természetesen mi magunk határoztuk meg és teszteltük, így a beadott kód működését és az abban szereplő megoldásokat teljes mértékben értjük és átlátjuk.
