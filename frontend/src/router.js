import Vue from 'vue'
import VueRouter from 'vue-router'


import Home from './components/Home.vue'
import SubmitSample from './components/SubmitSample.vue'
import Login from './components/Login.vue'
import Rescan from './components/Rescan.vue'
import Search from './components/search/Search.vue'
import ScanStatus from './components/ScanStatus.vue'
import store from './store';

Vue.use(VueRouter)

const routes = [
    {
        path: `${process.env.PUBLIC_PATH}/`, 
        component: Home,
        name: 'home',
        meta: {
            requiresAuth: true,
        }
    },
    {
        path: `${process.env.PUBLIC_PATH}/submit`,
        name: 'submit',
        component: SubmitSample
    },
    {
        path: `${process.env.PUBLIC_PATH}/login`,
        name: 'login',
        component: Login,
       
    },
    {
        path: `${process.env.PUBLIC_PATH}/rescan/:rootUID?`,
        name: 'rescan',
        component: Rescan,
        meta: {
            requiresAuth: true
        }
    },
    {
        path: `${process.env.PUBLIC_PATH}/search/:rootUID`,
        name: 'search',
        component: Search,
        meta: {
            requiresAuth: true
        }
    },
    {
        path: `${process.env.PUBLIC_PATH}/status/:submitID`,
        name: 'status',
        component: ScanStatus,
        meta: {
            requiresAuth: true
        }
    }
]

const router = new VueRouter({
    mode: 'history',
    routes
})

router.beforeEach((to, from, next) => {
    if (to.matched.some(record => record.meta.requiresAuth)) {
        if (store.state.loggedIn) {
            next()
            return
        }
        const loginPath = window.location.pathname;
        next(`${process.env.PUBLIC_PATH}/login?redirect=${loginPath}`)
    } else {
        next()
    }
})



export default router