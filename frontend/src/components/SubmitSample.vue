<template>
    <b-container fluid>
        <b-row class="text-center main-row justify-content-center">
            <b-col v-if="sendingFile" lg="5" md="8" sm="10" xs="12">
                <div style="margin-top: 2em"> uploading sample</div>
                <div style="margin-top: 1em">
                    <b-spinner variant="warning" type="grow" label="Spinning"></b-spinner>
                </div>
            </b-col>
            <b-col v-else-if="submitID" lg="5" md="8" sm="10" xs="12">
                <b-button variant="primary" @click="scanAnother">
                    Scan another Sample
                </b-button>
                <b-button variant="success" @click="checkOnScan">
                    Check on scan
                </b-button>
            </b-col>
            <b-col v-else lg="5" md="8" sm="10" xs="12">
                <h1>
                    Submit a Sample
                </h1>
                <b-form @submit.prevent="submitSample">
                    <b-form-group>
                        <b-form-file
                            v-model="file"
                            :state="Boolean(file)"
                            placeholder="Choose a file or drop it here..."
                            drop-placeholder="Drop file here..."
                        ></b-form-file>
                    </b-form-group>
                    <b-form-group label="Submission Options">
                        <b-form-checkbox-group
                            id="submission-options-checkbox-group"
                            v-model="selectedSubmissionOptions"
                            :options="submissionOptions"
                            name="submitOptions"
                        />
                    </b-form-group>
                    <b-form-group>
                        <b-form-textarea
                            v-if="showExternalMetadata"
                            id="external-metadata"
                            v-model="externalMetadata"
                            placeholder="External Metadata goes here in JSON format."
                            rows="4"
                            max-rows="12"
                        ></b-form-textarea>
                    </b-form-group>

                    <b-row>
                        <b-col>
                            <b-form-group label="Source">
                                <b-form-input placeholder="Submission source" v-model="source"/>
                            </b-form-group>
                        </b-col>
                        <b-col>
                            <b-form-group label="Content Type">
                                <b-form-input placeholder="Enter content-type here" v-model="contentType" />
                            </b-form-group>
                        </b-col>
                    </b-row>
                    
                    <b-button type="submit" 
                        id="submitSampleBtn"
                        variant="success"
                        >
                        Submit Sample
                    </b-button>
                </b-form>
                <div id="error">
                    {{error}}
                </div>
            </b-col>
        </b-row>
    </b-container>
</template>

<script>
import axios from 'axios'
export default {
    name: "SubmitSample",
    data() {
        return {
            file: null,
            selectedSubmissionOptions: [ "storage" ],
            submissionOptions: [
                { text: 'Submit to Splunk', value: 'splunk' },
                { text: 'Submit to Storage', value: 'storage' },
                { text: 'Add external metadata', value: 'metadata' },
            ],
            externalMetadata: '',
            source: 'webUI-unknown',
            contentType: '',
            submitID: null,
            sendingFile: false,
            error: ''
        }
    },
    created() {
        axios(`${process.env.REST_API_URL}/source`, {
            method: "get",
            withCredentials: true,
        })
        .then((resp) => {
            if (!resp || !resp.data || !resp.data.source) {
                return this.error="Failed to retrieve default source. Weird response."
            }
            this.source=resp.data.source
        })
        .catch((err) => {
            console.error(err)
            this.error= "Failed to retrieve default source."
        })
    },
    methods: {
        checkOnScan() {
            this.$router.push(`${process.env.PUBLIC_PATH}/status/${this.submitID}`)
            this.$router.push({ name: 'status', params: { submitID: this.submitID } })
        },
        scanAnother() {
            this.submitID = ''
        },
        submitSample() {
            this.error = ''

            const sOptions = this.selectedSubmissionOptions
            const submitSplunk = sOptions.includes('splunk')
            const submitStorage = sOptions.includes('storage')
            const includeMetadata = sOptions.includes('metadata')

            let externalMetaData = {}
            if (includeMetadata) {
                try {
                    externalMetaData = JSON.parse(this.externalMetadata)
                } catch(error) {
                    console.error(error)
                    this.error = "Provided external metadata is not valid JSON"
                    return
                }
            }
            const args = {}
            args['submit_to_splunk'] = submitSplunk
            args['submit_to_storage'] = submitStorage
            externalMetaData['args'] = args
            externalMetaData = JSON.stringify(externalMetaData)

            
            const fData = new FormData()
            fData.set("source", this.source)
            fData.set('file', this.file)
            fData.set('contentType', this.contentType)
            fData.set('extMetadata', externalMetaData)

            this.sendingFile = true
            axios({
                method: 'post',
                url: `${process.env.REST_API_URL}/scan/WebUI`,
                data: fData,
                headers: {'Content-Type': 'multipart/form-data' }
            })
            .then((response) => {
                this.sendingFile = false
                //handle success
                const data = response.data
                if (!data.submitID) {
                    this.error = "Submitted but didn't get a submissionID!"
                } else {
                    this.submitID = data.submitID
                }
            })
            .catch((err) => {
                this.sendingFile = false
                //handle error
                console.error(err)
                this.error = 'Failed to submit sample'
            })
        }
    },
    computed: {
        showExternalMetadata() 
        {
            return this.selectedSubmissionOptions.includes('metadata')
        }
    }
}
</script>

<style scoped>
form {
    margin-top: 2em;
}
.main-row {
    margin-top: 2.5em;
}
#submitSampleBtn {
    margin-top: 1em;
}
#error {
    margin-top: 1em;
    color: red;
}
</style>