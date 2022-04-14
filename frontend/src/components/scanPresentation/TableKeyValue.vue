<template>
    <div>
        <b-table class="text-left" sticky-header striped hover small responsive :items="keyVals"></b-table>
    </div>
</template>

<script>
export default {
    name: 'TableKeyValue',
    props: {
        keyVals: Array,
    },
    methods: {
    }
}
</script>

<style>
tr {
    cursor: pointer;
}
.b-table-sticky-header {
    max-height: 95% !important;
}
/* This should only mess with the first column */
td:nth-child(1) {
    max-width: 30vw;
    overflow-x: auto;
}

td:nth-child(2) {
    max-width: 40vw;
    overflow-x: auto;
}
</style>