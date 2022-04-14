<template>
    <b-navbar toggleable="sm" type="dark" variant="info" fixed>
        <b-navbar-toggle target="nav-text-collapse"></b-navbar-toggle>

        <b-navbar-brand :to="{name: 'home'}">LB</b-navbar-brand>

        <b-collapse id="nav-text-collapse" is-nav>
            <b-navbar-nav>
                <b-nav-item :to="{name: 'submit'}">Submit Sample</b-nav-item>
                <b-nav-item :to="{name: 'rescan'}" v-if="loggedIn">Rescan</b-nav-item>


            </b-navbar-nav>
            <b-navbar-nav class="ml-auto" v-if="loggedIn">
                <b-nav-item-dropdown right>
                    <template v-slot:button-content>
                        <em>Admin</em>
                    </template>
                    <b-dropdown-item @click="logout">logout</b-dropdown-item>
                </b-nav-item-dropdown>
                <b-nav-form @submit.prevent="search">
                    <b-form-input size="sm" class="mr-sm-2" v-model="query" placeholder="Search rootUID"></b-form-input>
                    <b-button size="sm" class="my-2 my-sm-0" type="submit">Search</b-button>
                </b-nav-form>
            </b-navbar-nav>
            <b-navbar-nav class="ml-auto" v-else>
                <b-nav-item-dropdown right>
                    <template v-slot:button-content>
                        <em>Anonymous</em>
                    </template>
                    <b-dropdown-item :to="{name: 'login'}">Login</b-dropdown-item>
                </b-nav-item-dropdown>
            </b-navbar-nav>
        </b-collapse>
    </b-navbar>
</template>

<script>
export default {
    name: 'NavBar',
    data() {
        return {
            query: '',
        }
    },
    methods: {
        logout() {
            this.$store.dispatch('logout')
            this.$router.push({ name: 'login' })
        },
        search() {
            const query = this.query.trim()
            this.query = ''
            if (this.$route.params.rootUID !== query) {
                this.$router.push({ name: 'search', params: { rootUID: query } })
            }
        }
    },
    computed: {
        loggedIn() {
            return this.$store.state.loggedIn
        }
    }
}
</script>

<style scoped>
.nav-link {
    font-weight: 600;
}
</style>
