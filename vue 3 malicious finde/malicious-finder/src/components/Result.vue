<template>
  <div class="page results">
    <header>
      <img src="../assets/logo.PNG" alt="Logo" class="logo" />
      <h1>Malicious Website Finder</h1>
      <nav>
        <RouterLink to="/">Home</RouterLink>
        <RouterLink to="/about">About</RouterLink>
      </nav>
    </header>

    <main>
      <div class="scan-container">
        <h2>Scan Results</h2>

        <p><strong>WHOIS result:</strong></p>
        <ul>
          <li><strong>Domain Name:</strong> {{ results.domainName || 'Not Available' }}</li>
          <li><strong>Creation Date:</strong> {{ results.creationDate }}</li>
          <li><strong>Expiration Date:</strong> {{ results.expirationDate }}</li>
          <li><strong>Name Servers:</strong> {{ results.nameServers?.join(', ') || 'Not Available' }}</li>
          <li><strong>Registrar:</strong> {{ results.registrar }}</li>
          <li><strong>Registrant Country:</strong> {{ results.registrantCountry }}</li>
          <li><strong>Updated Date:</strong> {{ results.updatedDate }}</li>
        </ul>


        <p><strong>ML Prediction:</strong> 
          <span :class="{ 'alert': results.mlPrediction === 'Phishing' }">{{ results.mlPrediction }}</span>
        </p>

        <p><strong>VirusTotal Result:</strong></p>
        <ul>
          <li><strong>Malicious:</strong> {{ results.malicious }}</li>
          <li><strong>Suspicious:</strong> {{ results.suspicious }}</li>
          <li><strong>Undetected:</strong> {{ results.undetected }}</li>
          <li><strong>Harmless:</strong> {{ results.harmless }}</li>
        </ul>

        <p><strong>Google Safe Browsing Result:</strong> {{ results.gsbResponse }}</p>
      </div>
    </main>
  </div>
</template>

<script>
import { computed } from "vue";
import { useStore } from "vuex";
;

const store = useStore();
const scanResults = computed(() => store.state.scanResults);

export default {
  setup() {
    const store = useStore();

    const results = computed(() => store.state.scanResults || {});

    return { results };
  }
};
</script>



<style scoped>
/* Background Image Styling */
.page.results {
  background: url('../../public/background_result.jpg') no-repeat center center fixed;
  background-size: cover;
  position: relative;
}

/* Dark overlay for readability */
.page.results::before {
  content: "";
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  z-index: -1;
}

/* Header Styling */
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
  text-shadow: 2px 2px 10px rgba(62, 79, 236, 0.8);
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

/* Scan Container Styling */
.scan-container {
  text-align: center;
  margin-top: 10%;
  background: rgba(0, 0, 0, 0.6);
  padding: 20px;
  border-radius: 10px;
  display: inline-block;
  color: white;
  width: 60%;
}

/* Alert Styling */
.alert {
  color: red;
  font-weight: bold;
}
</style>
