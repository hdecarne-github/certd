<script lang="ts">
	import { onMount } from 'svelte';
	import ui from '$lib/ui';

	onMount(() => {
		ui.navbarNavigate();
	});
</script>
