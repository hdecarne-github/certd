<script lang="ts">
	import { onMount } from 'svelte';
	import ui from '$lib/ui';
	import api, { StoreEntries, StoreEntry, StoreEntryDetails } from '$lib/api';
	import { selectedStoreEntry } from '../../../store';
	import cert from '$lib/cert';

	let storeEntries: StoreEntries = new StoreEntries();
	let storeEntryDetails: StoreEntryDetails = new StoreEntryDetails();

	onMount(() => {
		ui.navbarNavigate();
		api.storeEntries.get('..').then((response) => {
			storeEntries = response;
		});
		selectedStoreEntry.subscribe((name) => {
			if (name != '') {
				api.storeEntryDetails.get('..', name).then((response) => {
					storeEntryDetails = response;
				});
			}
		});
	});
</script>

<div class="container-fluid border-top">
	<div class="row align-items-start">
		<div class="flex-column flex-shrink-0 bg-body-tertiary" style="width:4.5rem;">
			<ul class="nav flex-column mb-auto text-center">
				<li class="nav-item">
					<a class="nav-link" href="../generate/">
						<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-plus-circle" viewBox="0 0 16 16">
							<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
							<path d="M8 4a.5.5 0 0 1 .5.5v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3A.5.5 0 0 1 8 4z"/>
						</svg>
					</a>
				</li>
				<li class="nav-item">
					<a class="nav-link" href=".">
						<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-arrow-up-circle" viewBox="0 0 16 16">
							<path fill-rule="evenodd" d="M1 8a7 7 0 1 0 14 0A7 7 0 0 0 1 8zm15 0A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-7.5 3.5a.5.5 0 0 1-1 0V5.707L5.354 7.854a.5.5 0 1 1-.708-.708l3-3a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 5.707V11.5z"/>
						</svg>
					</a>
				</li>
				<li class="nav-item">
					<a class="nav-link" href=".">
						<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-arrow-down-circle" viewBox="0 0 16 16">
							<path fill-rule="evenodd" d="M1 8a7 7 0 1 0 14 0A7 7 0 0 0 1 8zm15 0A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.5 4.5a.5.5 0 0 0-1 0v5.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V4.5z"/>
						</svg>
					</a>
				</li>
			</ul>
		</div>
		<div class="col-4 py-md-2">
			<div class="list-group list-group-checkable gap-2 border-0">
				{#each storeEntries.entries as entry}
				<input class="list-group-item-check pe-none" type="radio" name="entries" id="entry-{entry.name}" bind:group={$selectedStoreEntry}  value="{entry.name}">
				<label class="list-group-item rounded-3 py-3" for="entry-{entry.name}">
					{entry.name}
				  	{#if entry.ca}
				  	<span class="badge bg-primary">CA</span>
				  	{/if}
				  	{#if entry.key}
				  	<span class="badge bg-secondary">Key</span>
				  	{/if}
				  	{#if entry.crt}
				  	<span class="badge bg-secondary">CRT</span>
				  	{/if}
				  	{#if entry.csr}
				  	<span class="badge bg-secondary">CSR</span>
				  	{/if}
				  	{#if entry.crl}
				  	<span class="badge bg-secondary">CRL</span>
					{/if}
					<span class="d-block small opacity-50">{entry.dn}
					&nbsp;Not after: {entry.valid_to}
					</span>
				</label>
				{/each}
			</div>
		</div>
		<div class="col py-md-2">
			{#if storeEntryDetails.name != ''}
			<div class="card">
				<div class="card-body">
					{#if storeEntryDetails.crt}
					<h6 class="card-title">X.509 Certificate</h6>
					<ul class="list-group list-group-flush d-inline">
						<li class="list-group-item"><strong>Version:</strong> {storeEntryDetails.crt_details.version}</li>
						<li class="list-group-item"><strong>DN:</strong> {storeEntryDetails.dn}</li>
						<li class="list-group-item"><strong>Serial:</strong> {storeEntryDetails.crt_details.serial}</li>
						<li class="list-group-item"><strong>Key Type:</strong> {storeEntryDetails.crt_details.key_type}</li>
						<li class="list-group-item"><strong>Issuer:</strong> {storeEntryDetails.crt_details.issuer}</li>
						<li class="list-group-item"><strong>Signature algorithm:</strong> {storeEntryDetails.crt_details.sig_alg}</li>
						<li class="list-group-item"><strong>Not before:</strong> {storeEntryDetails.valid_from}</li>
						<li class="list-group-item"><strong>Not after:</strong> {storeEntryDetails.valid_to}</li>
						{#each storeEntryDetails.crt_details.extensions as extension}
						<li class="list-group-item"><strong>{extension[0]}:</strong> {extension[1]}</li>
						{/each}
					</ul>
					{/if}
				</div>
			</div>
			{/if}
		</div>
	</div>
</div>
