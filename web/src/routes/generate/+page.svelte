<script lang="ts">
	import { onMount } from 'svelte';
	import api, { StoreCAs, StoreLocalGenerate, StoreLocalIssuers } from '$lib/api';
	import cert from '$lib/cert';
	import { goto } from '$app/navigation';

    let storeCAs: StoreCAs = new StoreCAs();
    let storeLocalIssuers: StoreLocalIssuers = new StoreLocalIssuers();

    let selectedName: string;

    let selectedCA: string;

    const selectedLocalGenerate: StoreLocalGenerate = new StoreLocalGenerate();

    let selectedLocalValidFrom: string;
    let selectedLocalValidTo: string;

    let selectedRemoteDN: string;
    let selectedRemoteKeyType: string;

    let selectedACMEKeyType: string;
    let selectedACMEDomains: string;

	onMount(() => {
		api.storeCAs.get('..').then((response) => {
			storeCAs = response;
		});
        api.storeLocalIssuers.get('..').then((response) => {
            storeLocalIssuers = response
        })
        const defaultValidFrom = new Date();
        const defaultValidTo = defaultValidFrom;
        defaultValidTo.setFullYear(defaultValidTo.getFullYear()+1);
        selectedLocalValidFrom = cert.toValidityDateString(defaultValidFrom);
        selectedLocalValidTo = cert.toValidityDateString(defaultValidTo);
	});

    function onGenerate() {
        if (cert.isLocalCA(selectedCA)) {
            selectedLocalGenerate.name = selectedName;
            selectedLocalGenerate.ca = selectedCA;
            selectedLocalGenerate.valid_from = new Date(selectedLocalValidFrom);
            selectedLocalGenerate.valid_to = new Date(selectedLocalValidTo);
            selectedLocalGenerate.basic_constraint.enabled = true
            selectedLocalGenerate.basic_constraint.ca = true
            api.storeLocalGenerate.put('..', selectedLocalGenerate).then(() => { goto('../store'); });
        } else if (cert.isRemoteCA(selectedCA)) {

        } else if (cert.isACMECA(selectedCA)) {

        } else {

        }
    }

    function onCancel() {
        goto('../store');
    }
</script>

<div class="container m-3">
    <h1>Generate new certificate</h1>
    <form>
        <div class="mb-3">
            <label for="inputName" class="form-label">Name</label>
            <input id="inputName" class="form-control" bind:value={selectedName}>
        </div>
        <div class="mb-3">
            <label for="selectCA" class="form-label">Certificate Authority</label>
            <select id="selectCA" class="form-select" aria-label="Select CA" bind:value={selectedCA}>
                <option selected>&lt;select&gt;</option>
                {#each storeCAs.cas as ca}
                <option value="{ca.name}">{ca.name}</option>
                {/each}
            </select>
        </div>
        {#if cert.isLocalCA(selectedCA)}
        <div class="mb-3">
            <label for="inputLocalDN" class="form-label">Distinguished Name (DN)</label>
            <input id="inputLocalDN" class="form-control" bind:value={selectedLocalGenerate.dn}>
        </div>
        <div class="mb-3">
            <label for="selectLocalKeyType" class="form-label">Key Type</label>
            <select id="selectLocalKeyType" class="form-select" aria-label="Select key type" bind:value={selectedLocalGenerate.key_type}>
                <option value="">&lt;select&gt;</option>
                {#each cert.getLocalKeyTypes() as keyType}
                <option value="{keyType}">{keyType}</option>
                {/each}
            </select>
        </div>
        <div class="mb-3">
            <label for="selectLocalIssuer" class="form-label">Issuer</label>
            <select id="selectLocalIssuer" class="form-select" aria-label="Select issuer" bind:value={selectedLocalGenerate.issuer}>
                <option value="">&lt;self-signed&gt;</option>
                {#each storeLocalIssuers.issuers as issuer}
                <option value="{issuer.name}">{issuer.name}</option>
                {/each}
            </select>
        </div>
        <div class="mb-3">
            <label for="inputLocalValidFrom" class="form-label">Valid from</label>
            <input id="inputLocalValidFrom" class="form-control" type="date" bind:value={selectedLocalValidFrom}>
        </div>
        <div class="mb-3">
            <label for="inputLocalValidTo" class="form-label">Valid to</label>
            <input id="inputLocalValidTo" class="form-control" type="date" bind:value={selectedLocalValidTo}>
        </div>
        <div class="mb-3">
            <label for="localExtensions" class="form-label">Extensions</label>
            <div class="accordion" id="localExtensions">
                <div class="accordion-item">
                    <h3 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#localKeyUsageExtension" aria-expanded="false" aria-controls="Key Usage">
                        Key Usage
                        </button>
                    </h3>
                    <div id="localKeyUsageExtension" class="accordion-collapse collapse show" data-bs-parent="#localExtensions">
                        <div class="accordion-body">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="localKeyUsage" bind:checked={selectedLocalGenerate.key_usage.enabled}>
                                <label class="form-check-label" for="localKeyUsage">Enabled</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageDigitalSignature" bind:checked={selectedLocalGenerate.key_usage.digital_signature}>
                                <label class="form-check-label" for="localKeyUsageDigitalSignature">Digital Signature</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageContentCommitment" bind:checked={selectedLocalGenerate.key_usage.content_commitment}>
                                <label class="form-check-label" for="localKeyUsageContentCommitment">Content Commitment</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageKeyEncipherment" bind:checked={selectedLocalGenerate.key_usage.key_encipherment}>
                                <label class="form-check-label" for="localKeyUsageKeyEncipherment">Key Encipherment</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageDataEncipherment" bind:checked={selectedLocalGenerate.key_usage.data_encipherment}>
                                <label class="form-check-label" for="localKeyUsageDataEncipherment">Data Encipherment</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageKeyAgreement" bind:checked={selectedLocalGenerate.key_usage.key_agreement}>
                                <label class="form-check-label" for="localKeyUsageKeyAgreement">Key Agreement</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageCertSign" bind:checked={selectedLocalGenerate.key_usage.cert_sign}>
                                <label class="form-check-label" for="localKeyUsageCertSign">Cert Sign</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageCRLSign" bind:checked={selectedLocalGenerate.key_usage.crl_sign}>
                                <label class="form-check-label" for="localKeyUsageCRLSign">CRL Sign</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageEncipherOnly" bind:checked={selectedLocalGenerate.key_usage.encipher_only}>
                                <label class="form-check-label" for="localKeyUsageEncipherOnly">Encipher Only</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localKeyUsageDecipherOnly" bind:checked={selectedLocalGenerate.key_usage.decipher_only}>
                                <label class="form-check-label" for="localKeyUsageDecipherOnly">Decipher Only</label>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="accordion-item">
                    <h3 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#localExtKeyUsageExtension" aria-expanded="false" aria-controls="Extended Key Usage">
                        Extended Key Usage
                        </button>
                    </h3>
                    <div id="localExtKeyUsageExtension" class="accordion-collapse collapse" data-bs-parent="#accordionExample">
                        <div class="accordion-body">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="localExtKeyUsage" bind:checked={selectedLocalGenerate.ext_key_usage.enabled}>
                                <label class="form-check-label" for="localExtKeyUsage">Enabled</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageAny" bind:checked={selectedLocalGenerate.ext_key_usage.any}>
                                <label class="form-check-label" for="localExtKeyUsageAny">Any</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageServerAuth" bind:checked={selectedLocalGenerate.ext_key_usage.server_auth}>
                                <label class="form-check-label" for="localExtKeyUsageServerAuth">Server Auth</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageClientAuth" bind:checked={selectedLocalGenerate.ext_key_usage.client_auth}>
                                <label class="form-check-label" for="localExtKeyUsageClientAuth">Client Auth</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageCodeSigning" bind:checked={selectedLocalGenerate.ext_key_usage.code_signing}>
                                <label class="form-check-label" for="localExtKeyUsageCodeSigning">Code Signing</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageEmailProtection" bind:checked={selectedLocalGenerate.ext_key_usage.email_protection}>
                                <label class="form-check-label" for="localExtKeyUsageEmailProtection">Email Protection</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageIPSECEndSystem" bind:checked={selectedLocalGenerate.ext_key_usage.ipsec_end_system}>
                                <label class="form-check-label" for="localExtKeyUsageIPSECEndSystem">IPSEC End System</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageIPSECTunnel" bind:checked={selectedLocalGenerate.ext_key_usage.ipsec_tunnel}>
                                <label class="form-check-label" for="localExtKeyUsageIPSECTunnel">IPSECTunnel</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageIPSECUser" bind:checked={selectedLocalGenerate.ext_key_usage.ipsec_user}>
                                <label class="form-check-label" for="localExtKeyUsageIPSECUser">IPSEC User</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageTimeStamping" bind:checked={selectedLocalGenerate.ext_key_usage.time_stamping}>
                                <label class="form-check-label" for="localExtKeyUsageTimeStamping">Time Stamping</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageOCSPSigning" bind:checked={selectedLocalGenerate.ext_key_usage.ocsp_signing}>
                                <label class="form-check-label" for="localExtKeyUsageOCSPSigning">OCSP Signing</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageMicrosoftServerGatedCrypto" bind:checked={selectedLocalGenerate.ext_key_usage.microsoft_server_gated_crypto}>
                                <label class="form-check-label" for="localExtKeyUsageMicrosoftServerGatedCrypto">Microsoft Server Gated Crypto</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageNetscapeServerGatedCrypto" bind:checked={selectedLocalGenerate.ext_key_usage.netscape_server_gated_crypto}>
                                <label class="form-check-label" for="localExtKeyUsageNetscapeServerGatedCrypto">Netscape Server Gated Crypto</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageMicrosoftCommercialCodeSigning" bind:checked={selectedLocalGenerate.ext_key_usage.microsoft_commercial_code_signing}>
                                <label class="form-check-label" for="localExtKeyUsageMicrosoftCommercialCodeSigning">Microsoft Commercial Code Signing</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localExtKeyUsageMicrosoftKernelCodeSigning" bind:checked={selectedLocalGenerate.ext_key_usage.microsoft_kernel_code_signing}>
                                <label class="form-check-label" for="localExtKeyUsageMicrosoftKernelCodeSigning">Microsoft Kernel Code Signing</label>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="accordion-item">
                    <h3 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#localBasicConstraintExtension" aria-expanded="false" aria-controls="Basic Constraint">
                        Basic Constraint
                        </button>
                    </h3>
                    <div id="localBasicConstraintExtension" class="accordion-collapse collapse" data-bs-parent="#accordionExample">
                        <div class="accordion-body">
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" role="switch" id="localBasicConstraint" bind:checked={selectedLocalGenerate.basic_constraint.enabled}>
                                <label class="form-check-label" for="localBasicConstraint">Basic Constraint</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="" id="localBasicConstraintCA" bind:checked={selectedLocalGenerate.basic_constraint.ca}>
                                <label class="form-check-label" for="localBasicConstraintCA">CA</label>
                            </div>
                            <label for="localBasicConstraintPathLen" class="form-label">Path length constraint: {selectedLocalGenerate.basic_constraint.path_len}</label>
                            <input type="range" class="form-range" min="-1" max="10" id="localBasicConstraintPathLen" bind:value={selectedLocalGenerate.basic_constraint.path_len}>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {/if}
        {#if cert.isRemoteCA(selectedCA)}
        <div class="mb-3">
            <label for="inputRemoteDN" class="form-label">Distinguished Name (DN)</label>
            <input id="inputRemoteDN" class="form-control" bind:value={selectedRemoteDN}>
        </div>
        <div class="mb-3">
            <label for="selectRemoteKeyType" class="form-label">Key Type</label>
            <select id="selectRemoteKeyType" class="form-select" aria-label="Select key type" bind:value={selectedRemoteKeyType}>
                <option selected>&lt;select&gt;</option>
                {#each cert.getRemoteKeyTypes() as keyType}
                <option value="{keyType}">{keyType}</option>
                {/each}
            </select>
        </div>
        {/if}
        {#if cert.isACMECA(selectedCA)}
        <div class="mb-3">
            <label for="inputACMEDomains" class="form-label">Domain(s)</label>
            <input id="inputACMEDomains" class="form-control" bind:value={selectedACMEDomains}>
        </div>
        <div class="mb-3">
            <label for="selectACMEKeyType" class="form-label">Key Type</label>
            <select id="selectACMEKeyType" class="form-select" aria-label="Select Key Type" bind:value={selectedACMEKeyType}>
                <option selected>&lt;select&gt;</option>
                {#each cert.getACMEKeyTypes() as keyType}
                <option value="{keyType}">{keyType}</option>
                {/each}
            </select>
        </div>
        {/if}
        <button type="submit" class="btn btn-primary" on:click={onGenerate}>Continue</button>
        <button type="button" class="btn btn-secondary" on:click={onCancel}>Cancel</button>
    </form>
</div>
