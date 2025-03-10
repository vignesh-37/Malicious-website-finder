<script setup>
import { useRouter } from 'vue-router';

const router = useRouter();

const goToScan = () => {
  router.push('/scan');
};
</script>

<template>
  <div class="page home">
    <header>
      <img src="../assets/logo.PNG" alt="Logo" class="logo" />
      <h1>Malicious Website Finder</h1>
      <nav>
        <router-link to="/scan">Scan URL</router-link>
        <router-link to="/about">About</router-link>
      </nav>
    </header>

    <main>
      <video autoplay loop muted playsinline class="bg-video">
        <source src="/home_vid.mp4" type="video/mp4" />
        Your browser does not support the video tag.
      </video>

      <div class="main-content">
        <h2 class="content-heading"><span>&#9888;</span> Stay Safe Online: Detect Malicious Websites Instantly</h2>
        <p class="content-text"><i class='fas fa-shield-alt' style='font-size:36px'></i> Don’t risk your security! Enter a website URL to check if it’s safe or malicious.</p>
        <ul class="content-list">
          <li>&#9989; Instant Website Scanning</li>
          <li>&#9989; Real-Time Threat Detection</li>
          <li>&#9989; Deep Analysis</li>
        </ul>
        <button @click="goToScan">Scan URL &#x27A4;</button>
      </div>
    </main>

    <footer>
      <p>&copy; 2025 Malicious Website Finder</p>
    </footer>
  </div>
</template>

<style scoped>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  overflow-x: hidden;
  width: 100%;
  height: 100%;
}

.page {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  width: 100%;
  position: relative;
}

header {
  background-color: rgba(51, 51, 51, 0.9);
  color: white;
  padding: 1rem;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.logo {
  width: 60px;
  height: auto;
  margin-right: 1rem;
}

header h1 {
  margin: 0;
  font-size: 2rem;
  text-align: center;
  flex-grow: 1;
  font-weight: bold;
  background: linear-gradient(90deg, #2986f0, #12c1f7);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 2px 2px 10px rgba(62, 79, 236, 0.8);
  letter-spacing: 1px;
  transition: transform 0.3s ease-in-out;
}

header h1:hover {
  transform: scale(1.1);
  text-shadow: 4px 4px 15px rgb(15, 241, 230);
}

nav {
  display: flex;
  gap: 1rem;
}

nav a {
  color: rgb(16, 153, 233);
  text-decoration: none;
  transition: all 0.3s ease;
}

nav a:hover {
  text-decoration: underline;
  color: #11ccec;
}

.bg-video {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  z-index: -1;
}

main {
  color: rgb(244, 244, 248);
  flex-grow: 1;
  padding: 2rem;
  padding-top: 100px;
  text-align: center;
  width: 100%;
  min-height: calc(100vh - 200px);
  position: relative;
  z-index: 1;
}

.content-heading {
  padding: 1%;
  margin-bottom: 1%;
  font-size: 2rem;
}

.content-heading span {
  color: yellow;
}

.content-text {
  padding: 1%;
  margin-bottom: 3%;
  font-size: 1.5rem;
}

.content-list li {
  padding: 1%;
  margin-bottom: 1%;
  font-size: 1rem;
  list-style-type: none;
}

.main-content {
  position: absolute;
  top: 10%;
  left: 50%;
  transform: translateX(-50%);
}

button {
  padding: 12px 24px;
  margin-top: 5%;
  font-size: 1.2rem;
  font-weight: bold;
  color: white;
  background: rgb(0, 0, 255);
  border: 1px solid rgb(10, 178, 230);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.8s ease-in-out;
  text-transform: uppercase;
  box-shadow: 0 0 15px rgba(255, 0, 0, 0.7), 0 0 25px rgba(0, 255, 0, 0.7), 0 0 35px rgba(0, 0, 255, 0.7);
}

button:hover, button:focus {
  transform: scale(1.2);
  animation: rgbGlow 2s infinite alternate;
}

@keyframes rgbGlow {
  0% { box-shadow: 0 0 15px rgba(5, 219, 235, 0.7), 0 0 25px rgba(223, 3, 243, 0.7), 0 0 35px rgba(6, 248, 236, 0.7); }
  50% { box-shadow: 0 0 20px rgba(63, 5, 223, 0.9), 0 0 30px rgba(227, 8, 235, 0.9), 0 0 40px rgba(4, 228, 153, 0.9); }
  100% { box-shadow: 0 0 15px rgba(6, 212, 178, 0.7), 0 0 25px rgba(149, 4, 216, 0.7), 0 0 35px rgba(64, 230, 72, 0.7); }
}

footer {
  background-color: rgba(51, 51, 51, 0.9);
  color: white;
  padding: 1rem;
  text-align: center;
  width: 100%;
  height: 100px;
}
</style>
