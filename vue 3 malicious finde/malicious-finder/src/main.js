import { createApp } from 'vue';
import App from './App.vue';
import router from './router'; // Ensure 'router' is lowercase
import { createStore } from 'vuex';
import store from './store';

// const store = createStore({
//   state: {
//     scanResults: null,
//   },
//   mutations: {
//     setScanResults(state, results) {
//       state.scanResults = results;
//     },
//   },
//   actions: {
//     updateScanResults({ commit }, results) {
//       commit('setScanResults', results);
//     },
//   },
// });

const app = createApp(App);

app.use(store);
app.use(router); // Use router only once
app.mount('#app'); // Mount only once
