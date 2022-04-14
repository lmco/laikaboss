<template>
    <b-form @submit.prevent="submitSearch" class="container">
        <b-form-group label="Search a rootUID">
            <b-input-group>
                <b-form-input placeholder="Search a scan by rootUID" v-model="rootUID">
                </b-form-input>
                <b-input-group-append>
                    <b-button type="submit" variant="success">Search</b-button>
                </b-input-group-append>
            </b-input-group>
        </b-form-group>
    </b-form>
</template>

<script>
export default {
    name: 'LbSearchBar',
    data() {
        return {
            rootUID: "",
        }
    },
    methods: {
        submitSearch() 
        {
            const rootUID = this.rootUID.trim()
            this.$router.push({ name: 'search', params: { rootUID } })
        }
    }
}
</script>

<style scoped>
    .container {
        padding-top: 2em;
        padding-bottom: 2em;
    }
</style>