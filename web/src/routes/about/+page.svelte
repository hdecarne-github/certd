<script lang="ts">
    import { onMount } from 'svelte';
    import { navigate } from '$lib/ui';
	import api, { type AboutInfo } from '$lib/api';

    let aboutInfo:AboutInfo = {
        version: 'n/a',
        timestamp: 'n/a',
    };

    onMount(() => {
        navigate()
        api.about.get().then((response) => {
            aboutInfo = response
        })
    })
</script>
<div>
<table class="table table-striped">
    <tbody>
        <tr>
            <th scope="row">Version:</th>
            <td>{aboutInfo.version}</td>
        </tr>
        <tr>
            <th scope="row">Build timestamp:</th>
            <td>{aboutInfo.timestamp}</td>
        </tr>
    </tbody>
</table>
</div>