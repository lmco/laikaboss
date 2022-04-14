<template>
    <b-container fluid>
        <b-row class="text-center main-row justify-content-center">
            <b-col lg="5" md="8" sm="10" xs="12">
                <h1>Scan Status</h1>
                <div style="margin-top: 1em">
                    <b-spinner variant="warning" type="grow" label="Spinning"></b-spinner>
                </div>
                <div style="margin-top: 1em">
                    {{status}}
                </div>
            </b-col>
        </b-row>
    </b-container>
</template>

<script>
import axios from 'axios'
export default {
    name: 'ScanStatus',
    data() {
        return {
            status: 'scanning...',
        }
    },
    methods: {
        onLoad() {
            const submitID = this.$route.params.submitID
            this.checkInterval = setInterval(() => {
                axios.get(`${process.env.REST_API_URL}/status/${submitID}`)
                .then((resp) => {
                    const status = resp.data.status
                    switch (status) {
                        case 'submitted':
                        case 'processing':
                            break
                        case 'complete':
                            this.$router.push({ name: 'search', params: { rootUID: resp.data.rootUID } })
                            return clearInterval(this.checkInterval)
                        case 'timed out':
                            this.status = "Scan timed out"
                            return clearInterval(this.checkInterval)
                        case 'not found':
                            this.status = "Scan not found!"
                            return clearInterval(this.checkInterval)
                        default:
                            this.status = `Unknown status '${status}'! Refreshing might fix this issue`
                            return
                    }
                    this.status = status
                })
                .catch(err =>{
                    console.error(err)
                    this.status=`error. Check console for more info\nError: ${err}`
                    clearInterval(this.checkInterval)
                })
            }, 3000)
        }
    },
    mounted() {
        this.onLoad();
    },
    beforeDestroy() {
        clearInterval(this.checkInterval)
    }
}
</script>

<style scoped>
.main-row {
    margin-top: 2.5em;
}

</style>