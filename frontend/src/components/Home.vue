<template>
    <b-container>
        <b-row class="text-center main-row justify-content-center">
            <b-col lg="6" md="8" sm="10" xs="12">
                <h1>
                    LaikaBOSS
                </h1>
                <img :src="logo" />
                <p>CC: <strong>{{scanEmail}}</strong></p>
                <lb-search-bar />
            </b-col>
        </b-row>
    </b-container>
</template>

<script>
import LbSearchBar from './search/LbSearchBar.vue'
import logo from './logo.png'
export default {
    name: 'Home',
    components: {
        LbSearchBar,
    },
    data() {
        return {
            logo: logo,
            scanEmail: process.env.SCAN_EMAIL
        }
    }
}
</script>

<style scoped>
    .main-row {
        margin-top: 2.5em;
    }
</style>