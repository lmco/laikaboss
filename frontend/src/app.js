import "@babel/polyfill"

import Vue from 'vue'
import BootstrapVue from 'bootstrap-vue'
import { library } from '@fortawesome/fontawesome-svg-core'
import { faUserSecret } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
// custom imports
import App from './App.vue'
import store from './store'
import router from './router'

// CSS
import 'bootstrap-vue/dist/bootstrap-vue.css'
import 'bootstrap/dist/css/bootstrap.css'

Vue.use(BootstrapVue)
Vue.component('font-awesome-icon', FontAwesomeIcon)
new Vue({
    router,
    store,
    render: h => h(App)
}).$mount('#app')
