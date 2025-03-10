import { createRouter, createWebHistory } from 'vue-router';
import Home from '../components/Home.vue';
import Scan from '../components/Scan.vue';
import Results from '../components/Result.vue';
import About from '../components/About.vue';



const routes = [
    { path: '/', component: Home },
    { path: '/scan', component: Scan },
    { 
      path: '/results', 
      component: Results,
      beforeEnter: (to, from, next) => {
        if (sessionStorage.getItem('scanInitiated') === 'true') {
          sessionStorage.removeItem('scanInitiated'); // Clear flag after navigation
          next();
        } else {
          next('/'); // Redirect to home if accessed directly
        }
      }
    },
    { path: '/about', component: About }
  ];
  

const router = createRouter({
  history: createWebHistory(), // Enables clean URLs without #
  routes
});

// Function to mark scan as initiated
export function initiateScan() {
  sessionStorage.setItem('scanInitiated', 'true'); // Store in sessionStorage
}


export default router;
