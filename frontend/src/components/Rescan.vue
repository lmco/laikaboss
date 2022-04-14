<template>
    <b-container>
        <b-row class="text-center main-row justify-content-center">
            <b-col v-if="loading" lg="8" md="10" sm="11" xs="12">
                <b-spinner variant="warning" type="grow" label="Spinning"></b-spinner>
            </b-col>
            <b-col v-else-if="error" lg="8" md="10" sm="11" xs="12">
                <div class="err-msg">
                    {{error}}
                </div>
            </b-col>
            <b-col v-else lg="8" md="10" sm="11" xs="12">
                <h1>
                    Rescan
                </h1>
                <b-form @submit.prevent="rescan()">
                    <b-form-group label="Place a rootUID on separate lines to have them rescanned">
                        <b-form-textarea
                            placeholder="Enter rootUIDs here"
                            rows="6"
                            max-rows="10"
                            v-model="rootUIDs"
                        >
                        </b-form-textarea>
                    </b-form-group>
                    <b-form-group label="Submission Options">
                        <b-form-checkbox-group
                            id="submission-options-checkbox-group"
                            v-model="selectedSubmissionOptions"
                            :options="submissionOptions"
                            name="submitOptions"
                        />
                    </b-form-group>
                    <b-button variant="success" type="submit">
                        Rescan rootUIDs
                    </b-button>
                </b-form>
                <ul class="status-list">
                    <div v-for="(submission, sId) in submissionStatus" :key="sId">
                        <div v-for="(result, rId) in submission" :key="rId">
                            <li v-if="typeof result === 'string'">
                                {{rId}} : {{result}}
                            </li>
                            <li v-else>
                                {{rId}} : <a href="#" @click.prevent="statusCheck(result.scanID)">{{result.scanID}}</a>
                            </li>
                        </div>
                    </div>
                </ul>
            </b-col>
        </b-row>
    </b-container>
</template>

<script>
import axios from 'axios'
export default {
    name: 'Rescan',
    data() {
        return {
            loading: false,
            error: "",
            rootUIDs: "",
            submissionStatus: [],
            selectedSubmissionOptions: [ "submit_to_storage" ],
            submissionOptions: [
                { text: 'Submit all to Splunk', value: 'submit_to_splunk' },
                { text: 'Submit all to Storage', value: 'submit_to_storage' },
                { text: 'Save all subfiles', value: 'save_all_subfiles' },
            ],
        }
    },
    methods: {
        statusCheck(scanID)  {
            return this.$router.push({ name: 'status', params: { submitID: scanID }})
        },
        rescan() {
            const payload = {}
            payload['rootuids'] = this.rootUIDs.split(/\s+/)
        
            for (const option of this.selectedSubmissionOptions) {
                payload[option] = true
            }

            this.loading = true
            axios.post(`${process.env.REST_API_URL}/rescan`, payload, {withCredentials: true})
            .then((resp) => {
                this.loading = false
                if (!resp.data) {
                    return this.error = 'Got an unexpected reply'
                }
                this.submissionStatus = resp.data
            })
            .catch((err) => {
                this.loading = false
                console.error(err)
                this.error= 'failed to rescan. Check console for more info'
            })
        }
    },
    created() {
        this.rootUIDs = this.$route.params.rootUID
    }
}
</script>

<style>
.main-row {
    margin-top: 2.5em;
}
.err-msg {
    color: red;
    font-size: 1em;
}
.status-list {
    list-style-type: none;
}
</style>