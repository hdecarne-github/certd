<div class="container m-3">
	<div class="card" style="width: 35rem">
		<div class="card-body">
			<h5 class="card-title">About CertD</h5>
			<h6 class="card-subtitle mb-2 text-muted">
				Version {aboutInfo.version} ({aboutInfo.timestamp})
			</h6>
			<p class="card-text">
				Copyright CertD<br>
				Copyright (c) 2023 Holger de Carne and contributors,
			</p><p class="card-text">	
				All Rights Reserved.
			</p><p class="card-text">	
				This program is free software: you can redistribute it and/or modify<br>
				it under the terms of the GNU General Public License as published by<br>
				the Free Software Foundation, either version 3 of the License, or<br>
				(at your option) any later version.<br>
			</p><p class="card-text">	
				This program is distributed in the hope that it will be useful,<br>
				but WITHOUT ANY WARRANTY; without even the implied warranty of<br>
				MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the<br>
				GNU General Public License for more details.
			</p><p class="card-text">	
				You should have received a copy of the GNU General Public License<br>
				along with this program.  If not, see <a href="http://www.gnu.org/licenses">http://www.gnu.org/licenses</a>.
			</p>
			<a
				href="./store/"
				class="card-link text-decoration-none">Your certificate store</a>
			<a
				href="https://certd.carne.de"
				class="card-link text-decoration-none"
				target="_blank"
				rel="noreferrer">CertD Home</a>
			<a
				href="https://github.com/hdecarne-github/certd"
				class="card-link text-decoration-none"
				target="_blank"
				rel="noreferrer">
				View on GitHub&nbsp;
				<svg
					xmlns="http://www.w3.org/2000/svg"
					width="24"
					height="24"
					fill="currentColor"
					class="bi bi-github"
					viewBox="0 0 16 16"
				>
					<path
						d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"
					/>
				</svg>
			</a>
		</div>
	</div>
</div>

<script lang="ts">
	import { onMount } from 'svelte';
	import api, { type AboutInfo } from '$lib/api';

	let aboutInfo: AboutInfo = {
		version: 'n/a',
		timestamp: 'n/a'
	};

	onMount(() => {
		api.about.get('.').then((response) => {
			aboutInfo = response;
		});
	});
</script>
