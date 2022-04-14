<template>
    <div>
        <nav-bar />
        <router-view></router-view>
    </div>
</template>

<script>
import NavBar from './components/navigation/NavBar.vue'
export default {
    name: "App",
    components: {
        NavBar
    }
};
</script>

<style>
</style>
