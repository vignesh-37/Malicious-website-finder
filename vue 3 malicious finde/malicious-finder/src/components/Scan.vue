<template>
  <div class="page scan">
    <video autoplay muted loop class="background-video">
      <source src="/scan_vid.mp4" type="video/mp4" />
      Your browser does not support the video tag.
    </video>

    <header>
      <img src="../assets/logo.PNG" alt="Logo" class="logo" />
      <h1>Malicious Website Finder</h1>
      <nav>
        <RouterLink to="/">Home</RouterLink>
        <RouterLink to="/about">About</RouterLink>
      </nav>
    </header>

    <main>
      <div class="main-content">
        <h2 v-if="scanning">Scanning URL...</h2>
        <h2 v-else>Scan a URL for Potential Threats</h2>

        <!-- ✅ Input & Button (Hidden when scanning) -->
        <div v-if="!scanning" class="input-container">
          <input v-model="url" type="url" class="scan-input" required @focus="focused = true" @blur="focused = !url" />
          <label :class="{ active: focused || url }">Enter URL to scan</label>
        </div>

        <button v-if="!scanning" @click="scanUrl">Get Result</button>

        <!-- ✅ Scanning message -->
        <div v-if="scanning">
          <p class="scanning-text">Scanning: <span class="url-text">{{ url }}</span></p>
        </div>

        <p v-if="errorMessage" class="error-message">{{ errorMessage }}</p>
      </div>
    </main>

    <!-- ✅ Overlap Window (With Two Close Buttons) ✅ -->
    <div v-if="showResults" class="overlap-window">
      <div class="overlap-content">
        <!-- Close Button (Top-Right) -->
        <button class="close-btn top-right" @click="closeResults">✖</button>

        <h3 class="scan-head">Scan Results</h3>
        <h4><strong>URL:</strong>{{ url }}</h4>
        <p><strong>ML Prediction:</strong> <span :class="mlClass">{{ scanResults.ml_prediction ??  0}}</span></p>
        <!-- <p><strong>Google Safe Browsing:</strong> {{ scanResults.gsb_response }}</p> -->
        <p><strong>VirusTotal Detection:</strong></p>
        <ul>
          <li>Malicious: {{ scanResults.virusTotal.malicious ??  0}}</li>
          <li>Harmless: {{ scanResults.virusTotal.harmless ??  0}}</li>
          <li>Undetected: {{ scanResults.virusTotal.undetecte ??  0}}</li>
          <li>Harmless: {{ scanResults.virusTotal.harmless ??  0}}</li>
        </ul>


        <!-- Close Button (Bottom) -->
        <button class="close-btn bottom" @click="closeResults">Close</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from "vue";
import { useStore } from "vuex";
import { useRouter } from "vue-router";
import axios from "axios";

const store = useStore();
const url = ref("");
const errorMessage = ref("");
const scanning = ref(false);
const showResults = ref(false);
const scanResults = ref({});
const router = useRouter();
const focused = ref(false); 
const showInput = ref(false); 

// Show input field after 1 second (adjust as needed)
setTimeout(() => {
  showInput.value = true;
}, 1000);

const mlClass = computed(() => {
  if (!scanResults.value.ml_prediction) return "";
  return scanResults.value.ml_prediction.toLowerCase() === "malicious" ? "danger" : "safe";
});

const scanUrl = async () => {
  const hasHttp = url.value.includes("http://") || url.value.includes("https://");
  const hasTLD = /\.(com|org|net|info|biz|name|pro|edu|gov|mil|us|uk|ca|au|in|de|fr|jp|cn|ru|br|za|nz|mx|sg|tech|app|io|ai|dev|online|store|blog|design|law|health|hotel|travel|bank|finance|insurance|media|agency|realty|arpa|pharmacy|tv|me|cc)([/?]|$)/.test(url.value);
  const hasWWW = url.value.includes("www.");

  if (!url.value.trim()) {
    errorMessage.value = "Enter a URL.";
  } else if (!(hasHttp || hasTLD || hasWWW)) {
    errorMessage.value = "Invalid URL. Must contain 'http', 'https', a valid domain (e.g., .com, .net), or 'www'.";
  } else {
    errorMessage.value = "";
    scanning.value = true;
    showInput.value = false; // Hide input when scanning starts

    try {
      const response = await axios.post("http://localhost:3030/checkurl", { url: url.value });

      console.log("API Response:", response.data);

      store.dispatch("updateScanResults", response.data);
      scanResults.value = {
        ml_prediction: response.data.ml_prediction,
        gsb_response: response.data.gsb_response,
        virusTotal: response.data.Virus_Total_response,
      };
    } catch (error) {
      console.error("Error fetching results:", error.response ? error.response.data : error.message);
      errorMessage.value = "Failed to retrieve results. Try again later.";
      scanning.value = false;
      showInput.value = true; // Show input again if an error occurs
    }

    setTimeout(() => {
      scanning.value = false;
      showResults.value = true;
    }, 2000);
  }

  if (errorMessage.value) {
    setTimeout(() => {
      errorMessage.value = "";
    }, 5000);
  }
};


const closeResults = () => {
  showResults.value = false;
  url.value = "";
};
</script>

<style scoped>
/* Background Video */
.background-video {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  z-index: -1;
}

/* Header */
header {
  background-color: rgba(51, 51, 51, 0.8);
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


/* Main Content */
.main-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 100%;
  max-width: 600px;
  margin: 0 auto;
  padding: 3rem 1rem;
  text-align: center;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

.main-content p{
  color: red;
}

/* Input */
.input-container {
  position: relative;
  width: 100%;
  max-width: 400px;
  margin-bottom: 1.5rem;
}

.scan-input {
  width: 100%;
  padding: 12px 15px;
  font-size: 1rem;
  border: 2px solid #11ccec;
  border-radius: 8px;
  background-color: rgba(255, 255, 255, 0.8);
  outline: none;
}

.input-container label {
  position: absolute;
  left: 15px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 1rem;
  color: #555;
  transition: all 0.3s ease-in-out;
  pointer-events: none;
  background: white;
  padding: 0 5px;
}

.input-container label.active {
  top: 0;
  left: 10px;
  font-size: 0.8rem;
  color: #eceff0;
  background-color: #1b0de0;
}

button{  padding: 12px 24px;
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

/* ✅ Overlap Window */
.overlap-window {
  position: fixed;
  /* font-size: 1rem; */
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background: rgba(0, 0, 0, 0.9);
  color: white;
  padding: 20px;
  border-radius: 10px;
  height: 100%;
  max-height: 100%;
  width: 95%;
  max-width: 100%;
  z-index: 1001;
}

.overlap-window p{
  width: 100%;
  max-width: 100%;
  margin-left: 20%;
  font-size: 1rem;
  margin: 2%;
  text-align: left;
  margin-left: 20%;
  

}

.scan-head{
  color: #11ccec;
  font-size: 2rem;
}

.overlap-window ul li{
  width: 100%;
  max-width: 100%;
  margin-left: 20%;
  font-size: 1rem;
  margin: 2%;
  text-align: left;
  margin-left: 25%;
  list-style-type: none;
}


/* Close Buttons */
.close-btn {
  padding: 8px 16px;
  font-size: 1rem;
  font-weight: bold;
  background: red;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  margin-top: 10px;
}

.close-btn:hover {
  background: darkred;
}

/* Close Button (Top-Right) */
.close-btn.top-right {
  position: absolute;
  top: 10px;
  right: 10px;
}

/* Close Button (Bottom) */
.close-btn.bottom {
  display: block;
  margin: 20px auto 0;
}
</style>
