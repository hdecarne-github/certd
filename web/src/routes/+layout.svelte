<nav class="navbar navbar-expand-sm bg-body-tertiary">
    <div class="container-fluid">
        <span class="navbar-brand h1" >CertD</span>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="/">Store</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/automation">Automation</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/settings">Settings</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/about">About</a>
                </li>
            </ul>
        </div>
    </div>
</nav>
<slot />
<script lang="ts">
    import 'bootstrap/dist/css/bootstrap.min.css';
    import { onMount } from 'svelte';

    onMount(() => {
        import('bootstrap/dist/js/bootstrap.bundle.min.js');
    })
</script>
