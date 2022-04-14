<template>
    <b-row>
        <b-col class="text-left">
            <b-button variant="danger" @click.prevent="rescan">
                Rescan
            </b-button>
        </b-col>
        <b-col class="text-center">
            <h4 v-if="!memorializing">
                <b-badge v-if="isMemorialized=='yes'" variant="success" @click="memorialize()">Memorialized</b-badge>
                <b-badge v-if="isMemorialized=='unknown'" variant="warning" @click="memorialize()" href="#">Unknown</b-badge>
                <b-badge v-if="isMemorialized=='no'" variant="dark" @click="memorialize()" href="#">Not Memorialized</b-badge>
            </h4>
            <b-spinner v-else variant="warning" type="grow" label="Spinning"></b-spinner>
        </b-col>
        <b-col class="text-right">
            <b-dropdown id="dropdown-1" variant="success" right text="Download" class="m-md-2">
                <b-dropdown-item :href="downloadSampleUrl()" target="_blank">Download Sample</b-dropdown-item>
                <b-dropdown-item :href="downloadZipAttachments()" target="_blank">Download Zip of Interesting Attachments</b-dropdown-item>
                <b-dropdown-item :href="downloadJSONUrl()" target="_blank">Download JSON file</b-dropdown-item>
            </b-dropdown>
        </b-col>
    </b-row>
</template>

<script>
import axios from 'axios'
export default {
    props: {
        isMemorialized: String,
        rootUID: String,
        scanBucket: Object,
        storageBucket: Object
    },
    data() {
        return {
            memorializing: false,
        }
    },
    methods: {
        downloadJSONUrl() {
            return `${process.env.REST_API_URL}/json/${this.rootUID}`
        },
        downloadSampleUrl() {
            if (typeof this.storageBucket !== 'object') {
                return '#'
            }
            if (typeof this.storageBucket.bucket_name === 'undefined') {
                return '#'
            }
            return `${process.env.REST_API_URL}/sample/${this.storageBucket.bucket_name}/${this.storageBucket.sub_path}?original_filename=${this.rootUID}`
        },
        downloadZipAttachments() {
            return `${process.env.REST_API_URL}/zipattachments/${this.rootUID}`
        },
        rescan() {
            this.$router.push({name: 'rescan', params: {rootUID: this.rootUID}} )
        },
        memorialize() {
            this.memorializing = true
            axios.post(`${process.env.REST_API_URL}/memorialize/${this.rootUID}`, {}, {withCredentials: true})
            .then((resp) => {
                this.memorializing = false
                this.isMemorialized = 'yes'
            })
            .catch((err) => {
                this.memorializing = false
                this.isMemorialized = 'unknown'
                console.error(err)
            })
        }
    }
}
</script>

<style scoped>
</style>
