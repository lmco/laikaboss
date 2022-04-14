import vue from 'vue'
import Vuex from 'vuex'
import axios from 'axios'

vue.use(Vuex)

function deleteCookie(name) {
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;'
}

const store = new Vuex.Store({
    state: {
        loggedIn: document.cookie.match(/^(.*;)?\s*session_id\s*[^;]+(.*)?$/) ? true : false,
        loading: false,
    },
    mutations: {
        setLoading(state, val) {
            state.loading = val
        },
        setLoggedIn(state, val) {
            state.loggedIn = val
        }
    },
    actions: {
        login({commit}, user) {
            return new Promise((resolve, reject) => {
                commit('setLoading', true)
                axios.post(`${process.env.REST_API_URL}/auth`, {}, { auth: user, withCredentials: true})
                .then(resp => {
                    commit('setLoading', false)
                    axios.defaults.withCredentials = true;
                    commit('setLoggedIn', true)
                    resolve(resp)
                })
                .catch(err => {
                    commit('setLoading', false)
                    reject(err)
                })
            })
        },
        logout({commit}, user) {
            deleteCookie('session_id')
            commit('setLoggedIn', false)
        }
    }
})

export default store
