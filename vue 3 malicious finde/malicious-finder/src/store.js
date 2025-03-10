// src/store.js
import { createStore } from 'vuex';

const store = createStore({
  state: {
    scanResults: null,
  },
  mutations: {
    setScanResults(state, results) {
      state.scanResults = results;
    },
  },
  actions: {
    updateScanResults({ commit }, results) {
      commit('setScanResults', results);
    },
  },
  getters: {
    getScanResults: (state) => state.scanResults,
  },
});

export default store;
