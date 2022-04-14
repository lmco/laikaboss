<template>
    <b-container class="d-flex h-50 justify-content-center">
        <b-row class="text-center justify-content-center align-self-center">
            <b-col>
                <b-form v-if="!loading" @submit.prevent="login" class="main-form">
                    <h2> LaikaBOSS Login </h2>
                    <img :src="logo" />
                    <p>CC: <strong>{{scanEmail}}</strong></p>
                    <div v-if="useSSO">
                        <b-form-group>
                            <hr />
                        </b-form-group>
                        <b-form-group>
                            <b-button variant="outline-info" @click.prevent="singleSignOn">Single Sign On</b-button>
                        </b-form-group>
                    </div>
                    <b-form-group>
                        <hr />
                    </b-form-group>
                    <b-form-group>
                        <b-input-group prepend="username">
                            <b-form-input v-model="username" placeholder="Your LDAP username"></b-form-input>
                        </b-input-group>
                    </b-form-group>
                    <b-form-group>
                        <b-input-group prepend="password">
                            <b-form-input type="password" v-model="password" placeholder="Enter password here"></b-form-input>
                        </b-input-group>
                    </b-form-group>
                    <b-form-group>
                        <b-button type="submit" variant="success">Login</b-button>
                    </b-form-group>
                </b-form>
                <b-spinner v-if="loading" variant="warning" type="grow" label="Spinning"></b-spinner>
                <div class="errors-container" v-if="error">
                    {{ error }}
                </div>
            </b-col>
        </b-row>
    </b-container>

</template>

<script>
import logo from './logo.png'
export default {
    name: 'Login',
    data() {
        return {
            username: '',
            password: '',
            error: '',
            scanEmail: process.env.SCAN_EMAIL,
            logo: logo,
            useSSO: process.env.USE_SSO && process.env.USE_SSO === "true" ? true : false,
        }
    },
    methods: {
        singleSignOn() {
            let redirectBack = window.location.origin + "/" + process.env.PUBLIC_PATH
            if (this.$route.query.redirect) {
                redirectBack = redirectBack.slice(0, -1) + this.$route.query.redirect
            }
            window.location = process.env.REST_API_URL + '/sso?redirect=' + encodeURIComponent(redirectBack)
        },
        login() {
            this.error = ''
            const username  = this.username
            const password = this.password
            this.$store.dispatch('login', {
                username,
                password
            }).then(() => {
                if (this.$route.query.redirect) {
                    return this.$router.replace(this.$route.query.redirect)
                }
                this.$router.push({name: 'home'})
            })
            .catch((err) => {
                console.error(err)
                this.error = err
            })
        }
    },
    computed: {
        loading() {
            return this.$store.state.loading
        }
    }
}
</script>

<style scoped>
.main-form {
    margin-top: 1em;
}
h1 {
    margin-bottom: 1em;
}
.errors-container {
    color: red;
}
img {
    margin-bottom: 2em;
}
</style>
