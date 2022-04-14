<template>
    <div role="tablist" class="container-fluid" id="accordion-container">
        <b-badge v-if="expandedStatus != 'yes'" variant="light" href="#" @click.prevent="expand('yes')">Expand Sections</b-badge>
        <b-badge v-if="expandedStatus != 'minimized'" variant="light" href="#" @click.prevent="expand('minimized')">Minimize Sections</b-badge>
        <b-badge v-if="!expandedAllJson" variant="danger" href="#" v-b-tooltip.hover title="Careful! Large JSON takes time to render" @click.prevent="expandEverything()">Expand Everything</b-badge>
        <div style="margin: 0.5rem;">
            Nested JSON
            <b-form-checkbox style="display: inline-block;"
                id="flatten-checkbox"
                v-model="tableView"
                name="flatten-checkbox"
                value="yes"
                unchecked-value="no"
                @change="onChangeFlattenCheckbox"
                switch
                >
                Table View
            </b-form-checkbox>
        </div>

        <b-card no-body class="mb-1" v-if="interestingAttachments && interestingAttachments.length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.interesting-attachments variant="info">Interesting Attachments</b-button>
            </b-card-header>
            <b-collapse id="interesting-attachments" :visible="showSection(true)" role="tabpanel">
                <b-card-body>
                    <span v-for="(attachment, aIndex) in interestingAttachments" :key="aIndex">
                        <b-link :href="downloadAttachmentUrl(attachment)" target="_blank">{{attachment.file_name}} </b-link>, 
                    </span>
                </b-card-body>
            </b-collapse>
        </b-card>

        <b-card no-body class="mb-1" v-if="headerInfo.length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.header-info variant="info">Header Information</b-button>
            </b-card-header>
            <b-collapse id="header-info" :visible="showSection()" role="tabpanel">
                <b-card-body class="text-left">
                    <pre class="show-whitespace">{{headerInfo}}</pre>
                </b-card-body>
            </b-collapse>
        </b-card>
        
        <b-card no-body class="mb-1" v-if="emailTextPlain.length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.email-text-plain variant="info">Email Text Plain</b-button>
            </b-card-header>
            <b-collapse id="email-text-plain" :visible="showSection()" role="tabpanel">
                <b-card-body class="text-left">
                    <pre class="show-whitespace">{{emailTextPlain}}</pre>
                </b-card-body>
            </b-collapse>
        </b-card>

        <b-card no-body class="mb-1" v-if="emailTextFromHtml.length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.email-text-html variant="info">Email Text From HTML</b-button>
            </b-card-header>
            <b-collapse id="email-text-html" :visible="showSection()" role="tabpanel">
                <b-card-body class="text-left">
                    <!-- 
                        Make sure to NOT render emailTextPlain in v-html="varName" fashion or this application
                        WILL become vulnerable to XSS attacks.
                    -->
                    <pre class="show-whitespace">{{emailTextFromHtml}}</pre>
                </b-card-body>
            </b-collapse>
        </b-card>

        <b-card no-body class="mb-1" v-if="nonSummary && Object.keys(nonSummary).length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.non-summary variant="info">Non-Summary</b-button>
            </b-card-header>
            <b-collapse id="non-summary" :visible="showSection()" role="tabpanel">
                <b-card-body>
                    <div v-if="memorySizeOf(nonSummary) > 900000 && !forceRender">
                        Object is {{ memorySizeOf(nonSummary, true) }} in size. You might want to consider downloading the JSON instead. Click <a href="#" @click.prevent="toggleForceRender">here</a> to force a browser render.
                    </div>
                    <div v-else>
                        <b-badge v-if="jsonLevelNonSummary <= 2 && tableView == 'no'" variant="danger" v-b-tooltip.hover title="Careful! Large JSON takes time to render" href="#" @click.prevent="toggleJsonNonSummary">Expand JSON</b-badge>
                        <b-badge v-if="jsonLevelNonSummary == 20 && tableView == 'no'" variant="light" href="#" @click.prevent="toggleJsonNonSummary">Minimize JSON</b-badge>
                        <json-tree v-if="tableView == 'no'" :key="keyNonSummary()" :data="nonSummary" :level="jsonLevelNonSummary"  /> 
                        <table-key-value v-else :key="keyOtherSummary()" :keyVals="kvnonSummary" :rootUID="rootUID"/>
                    </div>
                </b-card-body>
            </b-collapse>
        </b-card>

        <b-card no-body class="mb-1" v-if="summary && Object.keys(summary).length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.summary variant="info">Summary</b-button>
            </b-card-header>
            <b-collapse id="summary" :visible="showSection(true)" role="tabpanel">
                <b-card-body class="summary-card-body">
                    <b-badge v-if="jsonLevelSummary <= 4 && tableView == 'no'" variant="warning" v-b-tooltip.hover title="Careful! Large JSON takes time to render" href="#" @click.prevent="toggleJsonSummary">Expand JSON</b-badge>
                    <b-badge v-if="jsonLevelSummary == 20 && tableView == 'no'" variant="light" href="#" @click.prevent="toggleJsonSummary">Minimize JSON</b-badge>
                    <json-tree v-else-if="tableView == 'no'" :key="keySummary()"  :data="summary" :level="jsonLevelSummary" />
                    <table-key-value v-else :key="keyOtherSummary()" :keyVals="kvsummary" />
                </b-card-body>
            </b-collapse>
        </b-card>

        <b-card no-body class="mb-1" v-if="unknownStatus && Object.keys(unknownStatus).length > 0">
            <b-card-header header-tag="header" class="p-1" role="tab">
                <b-button block v-b-toggle.unknown-format variant="info">Other Scan (Unknown Storage format)</b-button>
            </b-card-header>
            <b-collapse id="unknown-format" :visible="showSection(true)" role="tabpanel">
                <b-card-body class="default-card-body">
                    <b-badge v-if="jsonLevelOther <= 2" variant="danger" href="#" v-b-tooltip.hover title="Careful! Large JSON takes time to render" @click.prevent="toggleJsonOther">Expand JSON</b-badge>
                    <b-badge v-if="jsonLevelOther == 20" variant="light" href="#" @click.prevent="toggleJsonOther">Minimize JSON</b-badge>
                    <json-tree  v-if="tableView == 'no'" :key="keyOtherSummary()"  :data="unknownStatus" :level="jsonLevelOther" />
                    <table-key-value v-else :key="keyOtherSummary()" :keyVals="kvunknownStatus" />
                </b-card-body>
            </b-collapse>
        </b-card>
    </div>
</template>

<script>
import Vue from 'vue'
import TableKeyValue from './TableKeyValue.vue'
import JsonTree from './JsonTree.vue'
import tableFlatten from './table_flatten'

export default {
    name: 'ScanAccordion',
    props: {
        interestingAttachments: Array,
        headerInfo: String,
        emailTextPlain: String,
        emailTextFromHtml: String,
        initSummary: Object,
        initNonSummary: Array,
        initUnknownStatus: Object,
    },
    components: {
        JsonTree,
        TableKeyValue
    },
    computed: {
        rootUID: function () {
            return this.summary['rootUID']
        }
    },
    data() {
        return {
            expandedStatus: 'no', // can take on values 'yes', 'no', 'minimized'
            expandedAllJson: false, // show everything including json
            jsonLevelNonSummary: 0,
            jsonLevelSummary:  Object.keys(this.initSummary).length > 100 ? 1 : 2,
            jsonLevelOther: Object.keys(this.initUnknownStatus).length > 200 ?  1 : 2,
            tableView: localStorage.getItem('tableKeyValue') || Object.keys(this.initNonSummary).length > 200 ? 'no' : 'yes',
            summary: Vue.util.extend({}, this.initSummary),
            nonSummary: Vue.util.extend({}, this.initNonSummary),
            unknownStatus: Vue.util.extend({}, this.initUnknownStatus),
            kvsummary: [],
            kvnonSummary: [],
            kvunknownStatus: [],
            forceRender: false,
            explanationOpenedCount: 0
        }
    },
    mounted() {
        if (this.tableView === 'yes') {
            this.kvsummary = tableFlatten(this.summary)
            this.kvnonSummary = tableFlatten(this.nonSummary)
            this.kvunknownStatus = tableFlatten(this.unknownStatus)
        }
	},
    methods: {
        memorySizeOf(obj, humanReadable=false) {
            var bytes = 0

            function sizeOf(obj) {
                if(obj !== null && obj !== undefined) {
                    switch(typeof obj) {
                    case 'number':
                        bytes += 8
                        break
                    case 'string':
                        bytes += obj.length * 2
                        break
                    case 'boolean':
                        bytes += 4
                        break
                    case 'object':
                        var objClass = Object.prototype.toString.call(obj).slice(8, -1)
                        if(objClass === 'Object' || objClass === 'Array') {
                            for(var key in obj) {
                                if(!obj.hasOwnProperty(key)) continue
                                sizeOf(obj[key]);
                            }
                        } else bytes += obj.toString().length * 2
                        break
                    }
                }
                return bytes
            };
            if (humanReadable) {
                function formatByteSize(bytes) {
                    if(bytes < 1024) return bytes + " bytes"
                    else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KiB"
                    else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MiB"
                    else return(bytes / 1073741824).toFixed(3) + " GiB"
                };
                return formatByteSize(sizeOf(obj))
            }

            return sizeOf(obj)
        },
        toggleForceRender() {
            this.forceRender = true
        },
        keyNonSummary() {
            return "snn" + this.jsonLevelNonSummary
        },
        keySummary() {
            return 'ss' + this.jsonLevelSummary
        },
        keyOtherSummary() {
            return 'os' + this.jsonLevelOther
        },
        toggleJsonNonSummary() {
            this.jsonLevelNonSummary = this.jsonLevelNonSummary <= 2 ? 20 : 0
        },
        toggleJsonSummary() {
            this.jsonLevelSummary = this.jsonLevelSummary <= 4 ? 20 : 0
        },
        toggleJsonOther() {
            this.jsonLevelOther = this.jsonLevelOther <= 2 ? 20 : 0
        },
        expandEverything() {
            this.toggleJsonNonSummary()
            this.toggleJsonSummary()
            this.toggleJsonOther()  
            this.expandedAllJson = true
            this.expandedStatus = 'yes'  
        },
        onChangeFlattenCheckbox(newStatus) {
            localStorage.setItem('tableKeyValue', newStatus)
            if (newStatus === 'yes') {
                this.kvsummary = tableFlatten(this.summary)
                this.kvnonSummary = tableFlatten(this.nonSummary)
                this.kvunknownStatus = tableFlatten(this.unknownStatus)
            } else {
                this.tableView='no'
            }
        },
        downloadAttachmentUrl(attachment) {
            return `${process.env.REST_API_URL}/sample/${attachment.file_bucket}/${attachment.sub_path}?original_filename=${encodeURIComponent(attachment.file_name)}`
        },
        expand(value) {
            this.expandedStatus = value
        },
        showSection(defaultOpen=false, e=null) {
            defaultOpen = defaultOpen && this.expandedStatus !== 'minimized'
            return (this.expandedStatus == 'yes') ? true : defaultOpen
        },
    }
}
</script>

<style scoped>
#accordion-container {
    margin-bottom: 1em;
    padding-left: 4em;
    padding-right: 4em;
}

.show-whitespace {
    white-space: pre-wrap;
}
.card-body {
    max-height: 1500px;
    overflow: auto;
}

.summary-card-body {
    max-height: 5000px;
    overflow: auto;
}

</style>
