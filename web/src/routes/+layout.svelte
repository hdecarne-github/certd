<script lang="ts">
	import 'bootstrap/dist/css/bootstrap.min.css';
	import '../app.css';
	import { onMount } from 'svelte';
	onMount(() => {
		import('bootstrap/dist/js/bootstrap.bundle.min.js');
	});
</script>
<slot />
