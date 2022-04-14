<template>
    <b-container fluid>
        <b-row class="text-center main-row justify-content-center">
            <b-col lg="11" md="12" sm="12" xs="12" v-if="!loading">
                <div v-if="error" class="error-container">{{ error }}</div>
                <div v-else>
                    <h2>{{rootUID}}</h2>
                    <scan-actions v-if="scanResult" 
                        :isMemorialized="isMemorialized" 
                        :rootUID="rootUID" 
                        :scanBucket="scanBucket"
                        :storageBucket="storageBucket"
                    />
                    <scan-accordion v-if="scanResult" 
                        :interestingAttachments="interestingAttachments" 
                        :headerInfo="headerInfo"
                        :emailTextPlain="emailTextPlain"
                        :emailTextFromHtml="emailTextFromHtml"
                        :initSummary="splunkSummary"
                        :initNonSummary="splunkNonSummary"
                        :initUnknownStatus="unknownSplunkStatus"
                    />
                </div>
            </b-col>
            <b-col xs="12" class="text-center" v-else>
                <b-spinner variant="warning" type="grow" label="Spinning"></b-spinner>
            </b-col>
        </b-row>
    </b-container>
</template>

<script>
import axios from "axios";
import ScanActions from '../scanPresentation/ScanActions.vue'
import ScanAccordion from '../scanPresentation/ScanAccordion.vue'

function decodeBase64String(encoded_string) {
    try{
        //Workaround for this issue: https://stackoverflow.com/questions/51643482/utf-8-to-readable-characters
        const decodedContent = decodeURIComponent(escape(atob(encoded_string)))

        // Laikaboss GUI used to have to encode certain chars to html special chars, but this is not longer necessary,
        // because of VueJS. The content of a string, as long as the {{ varName }} syntax is used within vuejs, will
        // be automatically escaped.
        return decodedContent
    }
    catch(e) {
        console.error(e)
        if (e.code === 5) {
            return '<Failed to decode BASE64 content; Please download the text instead.>'
        }
        else if (e instanceof URIError) {
            //If there was an error with decodeURIComponent, then decode after mapping characters to ascii ranges
            return decodeURIComponent(
                atob(encoded_string).split('').map(
                    function(c) {                
                        if(c.charCodeAt(0) < 128){
                            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                        }
                        else {
                            return '';
                        }
                    }
                ).join('')
            );
        } 
        return '<Unknown Error. Download the text instead>'
    } 
}

export default {
    name: "Search",
    components: {
        ScanActions,
        ScanAccordion,
    },
    data() {
        return {
            rootUID: this.$route.params.rootUID || "",
            error: "",
            interestingAttachments: [],
            scanResult: false,
            isMemorialized: false,
            scanBucket: {},
            storageBucket: {},
            emailTextPlain: '',
            emailTextFromHtml: '',
            other: '',
            headerInfo: '',
            splunkSummary: {},
            splunkNonSummary: [],
            unknownSplunkStatus: {},
            loading: false,
            error: ''
        }
    },
    methods: {
        fetchScan(rootUID) {
            this.error = ''
            this.rootUID = rootUID
            if (!rootUID) {
                console.error("no rootUID provided")
                this.error='no rootUID provided'
                return;
            }
            const validUUID1Re = /\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/
            if (!validUUID1Re.exec(rootUID)) {
                this.error = `Not a valid rootUID`;
                return
            }
            this.loading = true
            axios.post(`${process.env.REST_API_URL}/search/${rootUID.trim()}`, {}, {withCredentials: true})
            .then((resp) => {
                this.loading = false
                this.unknownSplunkStatus = new Object()
                if (!resp.data || typeof resp.data !== "object") {
                    return this.error = "Did not get data"
                }
                const data = resp.data
                const { is_memorialized, header_info, scan_results, interesting_attachments, scan_bucket, storage_bucket } = data
                const { splunk_summary, splunk_nonsummary, email_text_from_html, email_text_plain } = scan_results
                this.interestingAttachments = interesting_attachments ? [ ...interesting_attachments ] : false
                this.scanBucket = scan_bucket || {}
                this.storageBucket = storage_bucket || {}
                this.isMemorialized = is_memorialized
                this.scanResult = true
                this.emailTextPlain = email_text_plain ? decodeBase64String (email_text_plain) : ''
                this.emailTextFromHtml = email_text_from_html ? decodeBase64String(email_text_from_html) : ''
                this.splunkSummary = splunk_summary || {}
                this.splunkNonSummary = splunk_nonsummary || []
                this.headerInfo = header_info || ''
                if (this.splunkNonSummary.length == 0) {
                    const other = {}
                    for (let [key, value] of Object.entries(scan_results)) {
                        if (['email_text_from_html', 'email_text_plain'].includes(key) == false) {
                            other[key] = value
                        }
                    }
                    this.unknownSplunkStatus = {...other}
                }
            })
            .catch(e => {
                this.loading = false
                console.error(e)
                this.error = e
            })
        }
    },
    created() {
        this.fetchScan(this.$route.params.rootUID)
    },
    beforeRouteUpdate(to, from, next) {
        this.fetchScan(to.params.rootUID)
        next()
    }
};
</script>

<style scoped>
.main-row {
    margin-top: 2.5em;
}
.error-container {
    color: red;
    font-size: 2em;
    padding: 1em;
}
</style>
